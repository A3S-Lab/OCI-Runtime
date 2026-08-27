use std::collections::BTreeMap;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, OperationId, Result, RuntimeEventKind, TeeAttestationRequest,
    TeeAttestationResponse, ValidateRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{
    StoredContainer, StoredOperation, StoredOperationKind, StoredOperationRequest,
    StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use super::operation::{request_digest, validate_deadline, validate_retry, RequestDigests};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict,
    AttestationOperationLookup, AttestationOperationPreparation, AttestationSource,
    DurableStateStore, CONTAINER_RECORD_FILE,
};

#[derive(Serialize)]
struct AttestationFingerprint<'a> {
    target: &'a ContainerTarget,
    report_data: &'a a3s_oci_sdk::TeeReportData,
}

impl DurableStateStore {
    /// Check durable replay before requiring the source generation to remain live.
    pub(crate) async fn lookup_attestation(
        &self,
        request: &TeeAttestationRequest,
    ) -> Result<AttestationOperationLookup> {
        request.validate()?;
        let digest = attestation_request_digest(request)?;
        let operation_id = &request.context.operation_id;
        let _guard = self.gate.lock().await;
        let Some(operation) = self.load_operation_if_present(operation_id).await? else {
            return Ok(AttestationOperationLookup::Pending);
        };
        validate_attestation_retry(&operation, request, &digest)?;
        match operation.outcome {
            StoredOperationStatus::Prepared => Ok(AttestationOperationLookup::Pending),
            StoredOperationStatus::SucceededAttestation { response } => {
                Ok(AttestationOperationLookup::Replayed(response))
            }
            StoredOperationStatus::Failed { error } => Err(error),
            _ => Err(invalid_outcome(operation_id)),
        }
    }

    /// Read and validate one exact TEE-backed source without reserving an operation.
    pub(crate) async fn attestation_source(
        &self,
        target: &ContainerTarget,
    ) -> Result<AttestationSource> {
        let generation = target.generation.ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "attest",
                "TEE attestation requires an exact generation",
            )
        })?;
        let _guard = self.gate.lock().await;
        let stored = self.load_stored_exact(&target.id, generation).await?;
        self.validate_attestation_source(&stored).await
    }

    pub(crate) async fn prepare_attestation(
        &self,
        request: &TeeAttestationRequest,
    ) -> Result<AttestationOperationPreparation> {
        request.validate()?;
        let digest = attestation_request_digest(request)?;
        let operation_id = &request.context.operation_id;
        let _guard = self.gate.lock().await;

        if let Some(operation) = self.load_operation_if_present(operation_id).await? {
            validate_attestation_retry(&operation, request, &digest)?;
            return match operation.outcome {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .load_stored_exact(&operation.container_id, operation.generation)
                        .await?;
                    let source = self.validate_attestation_source(&stored).await?;
                    claim_active_operation(
                        self,
                        &mut stored,
                        operation_id,
                        DurableMutation::ClaimAttestationOperation,
                        "attest",
                    )
                    .await?;
                    Ok(AttestationOperationPreparation::Resume(source))
                }
                StoredOperationStatus::SucceededAttestation { response } => {
                    Ok(AttestationOperationPreparation::Replayed(response))
                }
                StoredOperationStatus::Failed { error } => Err(error),
                _ => Err(invalid_outcome(operation_id)),
            };
        }

        validate_deadline(&request.context, "attest")?;
        let expected_generation = request.target.generation.ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "attest",
                "TEE attestation requires an exact generation",
            )
        })?;
        let mut stored = self.load_stored_container(&request.target.id).await?;
        if stored.record.generation != expected_generation {
            return Err(generation_conflict(
                &request.target.id,
                expected_generation,
                stored.record.generation,
                "attest",
            ));
        }
        let source = self.validate_attestation_source(&stored).await?;
        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: operation_id.clone(),
            kind: StoredOperationKind::Attest,
            container_id: stored.id.clone(),
            generation: stored.record.generation,
            process_id: None,
            request: Some(StoredOperationRequest::Attest(request.clone())),
            request_digest: digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareAttestationOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        claim_active_operation(
            self,
            &mut stored,
            operation_id,
            DurableMutation::ClaimAttestationOperation,
            "attest",
        )
        .await?;
        Ok(AttestationOperationPreparation::Prepared(source))
    }

    pub(crate) async fn complete_attestation(
        &self,
        operation_id: &OperationId,
        response: TeeAttestationResponse,
    ) -> Result<TeeAttestationResponse> {
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Attest {
            return Err(invalid_outcome(operation_id));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededAttestation { response } => {
                return Ok(response.as_ref().clone());
            }
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            _ => return Err(invalid_outcome(operation_id)),
        }
        let Some(StoredOperationRequest::Attest(request)) = operation.request.as_ref() else {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "attest",
                format!("TEE attestation operation {operation_id} has no retained request"),
            ));
        };
        let mut stored = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        let source = self.validate_attestation_source(&stored).await?;
        validate_attestation_response_bindings(&source, operation_id, request, &response)?;
        ensure_active_operation(&stored, operation_id, "attest")?;
        stored.active_operation = None;
        self.write_json(
            DurableMutation::CompleteAttestationContainer,
            &self
                .container_directory(&operation.container_id)
                .join(CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;

        let attributes = BTreeMap::from([
            (
                "operation-id".to_string(),
                operation_id.as_str().to_string(),
            ),
            (
                "tee-extension".to_string(),
                response.launch().technology().extension_name().to_string(),
            ),
            (
                "measurement".to_string(),
                response.measurement().as_str().to_string(),
            ),
            (
                "evidence-digest".to_string(),
                response.evidence().digest().as_str().to_string(),
            ),
        ]);
        self.append_operation_event(
            operation_id,
            "attested",
            response.target(),
            None,
            RuntimeEventKind::ContainerAttested,
            attributes,
        )
        .await?;

        operation.outcome = StoredOperationStatus::SucceededAttestation {
            response: Box::new(response.clone()),
        };
        self.write_json(
            DurableMutation::CompleteAttestationOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }

    pub(super) async fn validate_attestation_source(
        &self,
        stored: &StoredContainer,
    ) -> Result<AttestationSource> {
        if !matches!(
            stored.record.state.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "attest",
                format!(
                    "container {} generation {} must be created or running before TEE attestation",
                    stored.id, stored.record.generation.0
                ),
            ));
        }
        self.validate_attestation_bindings(stored).await
    }

    /// Rebuild immutable launch bindings without requiring the generation to remain live.
    pub(super) async fn validate_attestation_bindings(
        &self,
        stored: &StoredContainer,
    ) -> Result<AttestationSource> {
        if stored.record.isolation != a3s_oci_core::IsolationClass::DedicatedVm {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "attest",
                "TEE attestation source does not use dedicated-vm isolation",
            ));
        }
        let attachments = stored.attachments.as_ref().ok_or_else(|| {
            state_error(
                ErrorCode::FailedPrecondition,
                "attest",
                "TEE attestation source has no durable attachment contract",
            )
        })?;
        let bundle = self.load_bundle(stored).await?;
        let launch = attachments.tee_launch(&bundle)?.ok_or_else(|| {
            state_error(
                ErrorCode::FailedPrecondition,
                "attest",
                "container generation was not created with a TEE launch extension",
            )
        })?;
        Ok(AttestationSource {
            record: stored.record.clone(),
            launch,
        })
    }
}

fn validate_attestation_retry(
    operation: &StoredOperation,
    request: &TeeAttestationRequest,
    digest: &RequestDigests,
) -> Result<()> {
    let operation_id = &request.context.operation_id;
    validate_retry(
        operation,
        operation_id,
        StoredOperationKind::Attest,
        &request.target.id,
        digest,
        "attest",
    )?;
    if operation.request.as_ref() != Some(&StoredOperationRequest::Attest(request.clone())) {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "attest",
            format!(
                "operation ID {operation_id} was already used for a different TEE attestation request"
            ),
        ));
    }
    Ok(())
}

pub(super) fn validate_attestation_response_bindings(
    source: &AttestationSource,
    operation_id: &OperationId,
    request: &TeeAttestationRequest,
    response: &TeeAttestationResponse,
) -> Result<()> {
    response.validate_for_request(request)?;
    let attachments_digest = source.record.attachments_digest.as_deref().ok_or_else(|| {
        state_error(
            ErrorCode::FailedPrecondition,
            "attest",
            "TEE source has no attachment-manifest digest",
        )
    })?;
    if response.target() != &request.target
        || response.launch() != &source.launch
        || response.driver() != source.record.driver
        || response.config_digest().as_str() != source.record.config_digest
        || response.attachments_digest().as_str() != attachments_digest
    {
        return Err(state_error(
            ErrorCode::Conflict,
            "attest",
            format!(
                "TEE attestation operation {operation_id} returned evidence that differs from durable source bindings"
            ),
        ));
    }
    Ok(())
}

pub(super) fn attestation_request_digest(
    request: &TeeAttestationRequest,
) -> Result<RequestDigests> {
    request_digest(
        &AttestationFingerprint {
            target: &request.target,
            report_data: &request.report_data,
        },
        "attest",
    )
}

fn invalid_outcome(operation_id: &OperationId) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::FailedPrecondition,
        "attest",
        format!("TEE attestation operation {operation_id} has an invalid durable outcome"),
    )
}
