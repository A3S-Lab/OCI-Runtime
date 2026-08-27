mod attestation;
mod checkpoint;
mod create;
mod creation;
mod delete;
mod event;
mod failure;
mod filesystem;
mod filesystem_mutation;
mod freezer;
mod kill;
mod list;
mod model;
mod observe;
mod oci_state;
mod operation;
mod process;
mod process_io;
mod process_recovery;
mod restore;
mod start;
mod startup_audit;
mod update;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_core::{DriverKind, IsolationClass, LifecycleEvent, LifecycleState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CheckpointResponse, ContainerId, ContainerRecord, ContainerTarget, CreateAttachments,
    CreateRequest, ErrorCode, FileOp, Generation, IsolationRequest, OciBundle, OciSchemaValidator,
    OperationId, ProcessRecord, ProcessTarget, RestoreResponse, Result, RuntimeEventKind,
    TeeAttestationResponse, TeeLaunchRequest, ValidateRequest,
};
use tokio::sync::{Mutex, Notify};

#[cfg(test)]
use crate::fault::NoFaultInjector;
use crate::fault::{DurableMutation, FaultInjector};

use create::{create_request_digest, validate_create_retry};
use filesystem::{state_error, RootLock, StateFilesystem};
use model::{
    StoredContainer, StoredFilesystemMutationResponse, StoredGeneration, StoredOperation,
    StoredOperationKind, StoredOperationRequest, StoredOperationStatus, CONTAINER_SCHEMA_VERSION,
    GENERATION_SCHEMA_VERSION, OPERATION_SCHEMA_VERSION, OPERATION_SCHEMA_VERSION_V1,
    OPERATION_SCHEMA_VERSION_V2, OPERATION_SCHEMA_VERSION_V3, OPERATION_SCHEMA_VERSION_V4,
    OPERATION_SCHEMA_VERSION_V5,
};
use oci_state::{container_state, is_paused, rebuild_state};
use operation::validate_deadline;

const CONTAINER_RECORD_FILE: &str = "record.json";
const CONFIG_SNAPSHOT_FILE: &str = "config.json";
#[cfg(target_os = "macos")]
pub(crate) const DURABLE_OPERATION_SCHEMA_VERSION: &str = OPERATION_SCHEMA_VERSION;

/// Result of preparing an idempotent operation that returns container state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordOperationPreparation {
    /// This call durably created a new operation intent.
    Prepared(ContainerRecord),
    /// A matching operation intent exists and requires driver reconciliation.
    Resume(ContainerRecord),
    /// A matching operation already completed; this is its exact response.
    Replayed(ContainerRecord),
}

/// Result of preparing an idempotent OCI delete operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeletePreparation {
    /// This call durably created a new delete intent.
    Prepared(ContainerRecord),
    /// A matching delete intent requires driver reconciliation.
    Resume(ContainerRecord),
    /// A matching delete already completed.
    Replayed,
}

/// Result of preparing an idempotent exec operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessOperationPreparation {
    /// This call durably created a new exec intent.
    Prepared(ProcessRecord),
    /// A matching exec intent exists and requires driver reconciliation.
    Resume(ProcessRecord),
    /// A matching exec already completed; this is its exact response.
    Replayed(ProcessRecord),
}

/// Result of preparing an idempotent process signal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignalProcessPreparation {
    /// This call durably created a new signal intent.
    Prepared(ProcessTarget),
    /// A matching signal intent exists and requires driver reconciliation.
    Resume(ProcessTarget),
    /// A matching signal already completed.
    Replayed,
}

/// Durable process-wait lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessWaitPreparation {
    /// The terminal result was already committed.
    Replayed(a3s_oci_sdk::ExitStatus),
    /// The exact process target must be waited through the driver.
    Prepared(ProcessTarget),
}

/// Result of preparing a durable process-I/O mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessIoPreparation {
    /// This call durably created a new operation intent.
    Prepared(ProcessTarget),
    /// A matching operation intent requires driver reconciliation.
    Resume(ProcessTarget),
    /// A matching operation already completed.
    Replayed,
}

/// Result of preparing a durable mutation of one container filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FilesystemMutationPreparation<Response> {
    /// This call durably created a new operation intent.
    Prepared(ContainerTarget),
    /// A matching operation intent exists and requires driver reconciliation.
    Resume(ContainerTarget),
    /// A matching operation already completed; this is its exact response.
    Replayed(Response),
}

/// Result of preparing an idempotent immutable checkpoint operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckpointOperationPreparation {
    /// This call durably created a new checkpoint intent.
    Prepared(ContainerRecord),
    /// A matching intent exists and requires driver reconciliation.
    Resume(ContainerRecord),
    /// A matching checkpoint already completed; this is its exact response.
    Replayed(Box<CheckpointResponse>),
}

/// Validated durable source of one TEE attestation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttestationSource {
    pub(crate) record: ContainerRecord,
    pub(crate) launch: TeeLaunchRequest,
}

/// Result of checking an idempotent attestation before source preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttestationOperationLookup {
    /// No committed response exists; source and capability preflight is required.
    Pending,
    /// The exact attestation already completed and can replay without its source.
    Replayed(Box<TeeAttestationResponse>),
}

/// Result of preparing an idempotent TEE attestation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttestationOperationPreparation {
    Prepared(AttestationSource),
    Resume(AttestationSource),
    Replayed(Box<TeeAttestationResponse>),
}

/// Result of checking an idempotent restore before read-only artifact preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RestoreOperationLookup {
    /// No committed response exists; artifact preflight is required.
    Pending,
    /// The exact restore already completed and can replay without the artifact.
    Replayed(Box<RestoreResponse>),
}

/// Result of reserving one generation after restore artifact preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RestoreOperationPreparation {
    /// This call durably allocated a new restoring generation.
    Prepared(ContainerRecord),
    /// A matching restoring generation exists and requires driver reconciliation.
    Resume(ContainerRecord),
    /// A racing owner committed the exact response after preflight.
    Replayed(Box<RestoreResponse>),
}

/// Single-writer durable lifecycle store.
#[derive(Debug, Clone)]
pub(crate) struct DurableStateStore {
    root: Arc<PathBuf>,
    filesystem: Arc<StateFilesystem>,
    gate: Arc<Mutex<()>>,
    event_notify: Arc<Notify>,
    _root_lock: Arc<RootLock>,
    faults: Arc<dyn FaultInjector>,
}

impl DurableStateStore {
    /// Open or initialize one absolute runtime-owned state root.
    #[cfg(test)]
    pub(crate) async fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_fault_injector(root, Arc::new(NoFaultInjector)).await
    }

    pub(crate) async fn open_with_fault_injector(
        root: impl AsRef<Path>,
        faults: Arc<dyn FaultInjector>,
    ) -> Result<Self> {
        let (filesystem, root_lock) = filesystem::open_root(root.as_ref(), faults.as_ref()).await?;
        let store = Self {
            root: Arc::new(filesystem.root().to_path_buf()),
            filesystem,
            gate: Arc::new(Mutex::new(())),
            event_notify: Arc::new(Notify::new()),
            _root_lock: root_lock,
            faults,
        };
        store.audit_startup_state().await?;
        Ok(store)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        self.root.as_ref()
    }

    /// Durably reserve an OCI create before invoking a driver.
    #[cfg(test)]
    pub(crate) async fn prepare_create(
        &self,
        request: &CreateRequest,
        driver: DriverKind,
    ) -> Result<RecordOperationPreparation> {
        self.prepare_create_with_inherited_descriptors(request, driver, None)
            .await
    }

    /// Durably reserve a create with its stable process-local attachment schema.
    pub(crate) async fn prepare_create_with_inherited_descriptors(
        &self,
        request: &CreateRequest,
        driver: DriverKind,
        inherited_descriptors: Option<&a3s_oci_agent_protocol::AgentInheritedDescriptorSchema>,
    ) -> Result<RecordOperationPreparation> {
        request.validate()?;
        let request_digest = create_request_digest(request, inherited_descriptors)?;
        let _guard = self.gate.lock().await;

        if let Some(operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_create_retry(&operation, request, &request_digest)?;
            return match operation.outcome.clone() {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .reconcile_prepared_create(request, driver, operation.generation)
                        .await?;
                    claim_active_operation(
                        self,
                        &mut stored,
                        &request.context.operation_id,
                        DurableMutation::ClaimCreateOperation,
                        "prepare-create",
                    )
                    .await?;
                    self.append_container_event(
                        "creating",
                        &ContainerTarget::exact(request.id.clone(), stored.record.generation),
                        RuntimeEventKind::ContainerCreating,
                        BTreeMap::new(),
                    )
                    .await?;
                    Ok(RecordOperationPreparation::Resume(stored.record))
                }
                StoredOperationStatus::Succeeded { response } => {
                    self.reconcile_succeeded_create(operation, response).await
                }
                StoredOperationStatus::Failed { error } => {
                    self.reconcile_failed_create(&operation).await?;
                    Err(error)
                }
                StoredOperationStatus::SucceededProcess { .. }
                | StoredOperationStatus::SucceededFilesystem { .. }
                | StoredOperationStatus::SucceededCheckpoint { .. }
                | StoredOperationStatus::SucceededRestore { .. }
                | StoredOperationStatus::SucceededAttestation { .. }
                | StoredOperationStatus::SucceededEmpty => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "prepare-create",
                    format!(
                        "create operation {} has an invalid empty outcome",
                        request.context.operation_id
                    ),
                )),
            };
        }
        validate_deadline(&request.context, "prepare-create")?;

        let container_directory = self.container_directory(&request.id);
        if self.filesystem.path_exists(&container_directory).await? {
            return Err(state_error(
                ErrorCode::AlreadyExists,
                "prepare-create",
                format!("container {} already exists", request.id),
            ));
        }

        let generation = self.next_generation(&request.id).await?;
        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: StoredOperationKind::Create,
            container_id: request.id.clone(),
            generation,
            process_id: None,
            request: None,
            request_digest: request_digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareCreateOperation,
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;

        let stored = self
            .reconcile_prepared_create(request, driver, generation)
            .await?;
        let record = stored.record;
        self.append_container_event(
            "creating",
            &ContainerTarget::exact(request.id.clone(), record.generation),
            RuntimeEventKind::ContainerCreating,
            BTreeMap::new(),
        )
        .await?;
        Ok(RecordOperationPreparation::Prepared(record))
    }

    async fn reconcile_prepared_create(
        &self,
        request: &CreateRequest,
        driver: DriverKind,
        generation: Generation,
    ) -> Result<StoredContainer> {
        self.reconcile_prepared_container(
            &request.id,
            &request.bundle,
            request.isolation.class(),
            &request.attachments,
            driver,
            generation,
            &request.context.operation_id,
            creation::CreationProfile {
                operation: "reconcile-create",
                store_config: DurableMutation::StoreCreateConfig,
                store_container: DurableMutation::StoreCreatingContainer,
            },
        )
        .await
    }

    async fn reconcile_succeeded_create(
        &self,
        mut operation: StoredOperation,
        response: ContainerRecord,
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
        let durable_status = *stored.record.state.status();
        if !matches!(
            durable_status,
            ContainerState::Created | ContainerState::Running
        ) {
            return Ok(RecordOperationPreparation::Replayed(response));
        }
        if stored.record.state.pid() == response.state.pid() {
            return Ok(RecordOperationPreparation::Replayed(response));
        }
        let active_allows_rebind = match stored.active_operation.as_ref() {
            Some(operation_id) => {
                let active = self.load_operation(operation_id).await?;
                matches!(
                    (durable_status, active.kind),
                    (
                        ContainerState::Created,
                        StoredOperationKind::Start | StoredOperationKind::Attest,
                    ) | (
                        ContainerState::Running,
                        StoredOperationKind::Kill
                            | StoredOperationKind::Pause
                            | StoredOperationKind::Resume
                            | StoredOperationKind::Update
                            | StoredOperationKind::File
                            | StoredOperationKind::Filesystem
                            | StoredOperationKind::Checkpoint
                            | StoredOperationKind::Attest
                    )
                ) && active.container_id == stored.id
                    && active.generation == stored.record.generation
                    && matches!(active.outcome, StoredOperationStatus::Prepared)
            }
            None => true,
        };
        if !active_allows_rebind || *response.state.status() != ContainerState::Created {
            return Err(state_error(
                ErrorCode::Conflict,
                "reconcile-succeeded-create",
                format!(
                    "completed create operation {} differs from its durable container record",
                    operation.operation_id
                ),
            ));
        }
        let mut expected_state =
            rebuild_state(&response.state, durable_status, *stored.record.state.pid())?;
        if is_paused(&stored.record.state) {
            expected_state = oci_state::rebuild_paused_state(&expected_state, true)?;
        }
        let expected_durable = ContainerRecord {
            state: expected_state,
            ..response.clone()
        };
        if expected_durable != stored.record {
            return Err(state_error(
                ErrorCode::Conflict,
                "reconcile-succeeded-create",
                format!(
                    "completed create operation {} changed beyond its recovered process identity: durable {:?}, reconstructed {:?}",
                    operation.operation_id, stored.record, expected_durable
                ),
            ));
        }
        let rebound_response = ContainerRecord {
            state: rebuild_state(
                &response.state,
                ContainerState::Created,
                *stored.record.state.pid(),
            )?,
            ..response
        };
        operation.outcome = StoredOperationStatus::Succeeded {
            response: rebound_response.clone(),
        };
        self.write_json(
            DurableMutation::CompleteCreateOperation,
            &self.operation_path(&operation.operation_id),
            &operation,
        )
        .await?;
        Ok(RecordOperationPreparation::Replayed(rebound_response))
    }

    /// Commit driver create completion with the prepared init-process PID.
    pub(crate) async fn complete_create(
        &self,
        operation_id: &OperationId,
        pid: i32,
    ) -> Result<ContainerRecord> {
        if pid <= 0 {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "complete-create",
                format!("created container PID must be positive; received {pid}"),
            ));
        }
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Create {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "complete-create",
                format!("operation {operation_id} is not an OCI create"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::Succeeded { response } => return Ok(response.clone()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededFilesystem { .. }
            | StoredOperationStatus::SucceededCheckpoint { .. }
            | StoredOperationStatus::SucceededRestore { .. }
            | StoredOperationStatus::SucceededAttestation { .. }
            | StoredOperationStatus::SucceededEmpty => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-create",
                    format!("create operation {operation_id} has an invalid empty outcome"),
                ));
            }
        }

        let mut stored = self.load_stored_container(&operation.container_id).await?;
        if stored.record.generation != operation.generation {
            return Err(generation_conflict(
                &operation.container_id,
                operation.generation,
                stored.record.generation,
                "complete-create",
            ));
        }

        match *stored.record.state.status() {
            ContainerState::Creating => {
                let lifecycle = LifecycleState::Creating
                    .transition(LifecycleEvent::CreateCompleted)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "complete-create",
                            error.to_string(),
                        )
                    })?;
                let status = container_state(lifecycle);
                stored.record.state = rebuild_state(&stored.record.state, status, Some(pid))?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
            }
            ContainerState::Created if *stored.record.state.pid() == Some(pid) => {}
            ContainerState::Created => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "complete-create",
                    format!(
                        "container {} was already committed with PID {:?}, not {pid}",
                        operation.container_id,
                        stored.record.state.pid()
                    ),
                ));
            }
            status => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-create",
                    format!(
                        "container {} cannot complete create while {status}",
                        operation.container_id
                    ),
                ));
            }
        }

        ensure_active_operation(&stored, operation_id, "complete-create")?;
        stored.active_operation = None;
        self.write_json(
            DurableMutation::CompleteCreateContainer,
            &self
                .container_directory(&operation.container_id)
                .join(CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;
        let response = stored.record.clone();
        self.append_container_event(
            "created",
            &ContainerTarget::exact(operation.container_id.clone(), operation.generation),
            RuntimeEventKind::ContainerCreated,
            BTreeMap::from([("pid".to_string(), pid.to_string())]),
        )
        .await?;
        operation.outcome = StoredOperationStatus::Succeeded {
            response: response.clone(),
        };
        self.write_json(
            DurableMutation::CompleteCreateOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }

    /// Load a durable record and enforce an optional generation fence.
    pub(crate) async fn state(&self, target: &ContainerTarget) -> Result<ContainerRecord> {
        let _guard = self.gate.lock().await;
        let stored = self.load_stored_container(&target.id).await?;
        if let Some(expected) = target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &target.id,
                    expected,
                    stored.record.generation,
                    "state",
                ));
            }
        }
        Ok(stored.record)
    }

    /// Reconstruct the immutable bundle from the durable config snapshot.
    pub(crate) async fn bundle(&self, target: &ContainerTarget) -> Result<OciBundle> {
        let _guard = self.gate.lock().await;
        let stored = self.load_stored_container(&target.id).await?;
        if let Some(expected) = target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &target.id,
                    expected,
                    stored.record.generation,
                    "load-durable-bundle",
                ));
            }
        }
        self.load_bundle(&stored).await
    }

    /// Load the exact attachment contract bound to a durable generation.
    pub(crate) async fn attachment_contract(
        &self,
        target: &ContainerTarget,
    ) -> Result<Option<CreateAttachments>> {
        let _guard = self.gate.lock().await;
        let stored = self.load_stored_container(&target.id).await?;
        if let Some(expected) = target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &target.id,
                    expected,
                    stored.record.generation,
                    "load-durable-attachments",
                ));
            }
        }
        Ok(stored.attachments)
    }

    async fn next_generation(&self, id: &ContainerId) -> Result<Generation> {
        let path = self.generation_path(id);
        let last = if self.filesystem.path_exists(&path).await? {
            let stored: StoredGeneration = self.filesystem.read_json(&path).await?;
            if stored.schema_version != GENERATION_SCHEMA_VERSION || stored.id != *id {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "allocate-generation",
                    format!("invalid generation record for {id}"),
                ));
            }
            stored.last_generation.0
        } else {
            0
        };
        let next = last.checked_add(1).ok_or_else(|| {
            state_error(
                ErrorCode::ResourceExhausted,
                "allocate-generation",
                format!("container {id} exhausted its generation counter"),
            )
        })?;
        let generation = Generation(next);
        self.write_json(
            DurableMutation::AllocateGeneration,
            &path,
            &StoredGeneration {
                schema_version: GENERATION_SCHEMA_VERSION.to_string(),
                id: id.clone(),
                last_generation: generation,
            },
        )
        .await?;
        Ok(generation)
    }

    async fn load_operation_if_present(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<StoredOperation>> {
        let path = self.operation_path(operation_id);
        if !self.filesystem.path_exists(&path).await? {
            return Ok(None);
        }
        self.load_operation(operation_id).await.map(Some)
    }

    async fn load_operation(&self, operation_id: &OperationId) -> Result<StoredOperation> {
        let path = self.operation_path(operation_id);
        if !self.filesystem.path_exists(&path).await? {
            return Err(state_error(
                ErrorCode::NotFound,
                "load-operation",
                format!("operation {operation_id} does not exist"),
            ));
        }
        let operation: StoredOperation = self.filesystem.read_json(&path).await?;
        if !matches!(
            operation.schema_version.as_str(),
            OPERATION_SCHEMA_VERSION_V1
                | OPERATION_SCHEMA_VERSION_V2
                | OPERATION_SCHEMA_VERSION_V3
                | OPERATION_SCHEMA_VERSION_V4
                | OPERATION_SCHEMA_VERSION_V5
                | OPERATION_SCHEMA_VERSION
        ) || operation.operation_id != *operation_id
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-operation",
                format!("invalid durable operation record for {operation_id}"),
            ));
        }
        validate_stored_operation_shape(&operation)?;
        Ok(operation)
    }

    async fn load_stored_exact(
        &self,
        id: &ContainerId,
        generation: Generation,
    ) -> Result<StoredContainer> {
        let stored = self.load_stored_container(id).await.map_err(|error| {
            if error.code == ErrorCode::NotFound {
                state_error(
                    ErrorCode::Unavailable,
                    "reconcile-operation",
                    format!(
                        "operation journal references missing container {id} generation {}",
                        generation.0
                    ),
                )
                .retryable(true)
            } else {
                error
            }
        })?;
        if stored.record.generation != generation {
            return Err(generation_conflict(
                id,
                generation,
                stored.record.generation,
                "reconcile-operation",
            ));
        }
        Ok(stored)
    }

    async fn load_stored_container(&self, id: &ContainerId) -> Result<StoredContainer> {
        let directory = self.container_directory(id);
        if !self.filesystem.path_exists(&directory).await? {
            return Err(state_error(
                ErrorCode::NotFound,
                "load-container-state",
                format!("container {id} does not exist"),
            ));
        }
        self.load_stored_container_from_directory(id, &directory)
            .await
    }

    async fn load_stored_container_from_directory(
        &self,
        id: &ContainerId,
        directory: &Path,
    ) -> Result<StoredContainer> {
        self.filesystem
            .ensure_plain_directory(directory, "container state directory")
            .await?;
        self.filesystem
            .set_private_directory_permissions(directory)
            .await?;
        let path = directory.join(CONTAINER_RECORD_FILE);
        if !self.filesystem.path_exists(&path).await? {
            return Err(state_error(
                ErrorCode::Unavailable,
                "reconcile-container-state",
                format!("container {id} has no durable record"),
            )
            .retryable(true));
        }
        let stored: StoredContainer = self.filesystem.read_json(&path).await?;
        if stored.schema_version != CONTAINER_SCHEMA_VERSION
            || stored.id != *id
            || stored.record.generation.0 == 0
            || stored.record.state.id() != id.as_str()
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-container-state",
                format!("invalid durable container record for {id}"),
            ));
        }
        OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
        let bundle = self.load_bundle_from_directory(&stored, directory).await?;
        if bundle.config_digest() != stored.record.config_digest {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-container-state",
                format!("container {id} configuration digest does not match its snapshot"),
            ));
        }
        match (&stored.attachments, &stored.record.attachments_digest) {
            (Some(attachments), Some(expected_digest)) => {
                attachments.validate(&bundle)?;
                let isolation = match stored.record.isolation {
                    IsolationClass::DedicatedVm => IsolationRequest::DedicatedVm,
                    IsolationClass::SharedHostKernel => IsolationRequest::SharedHostKernel,
                    IsolationClass::SharedGuestKernel => IsolationRequest::SharedGuestKernel {
                        trust_domain: attachments
                            .guest_session()
                            .ok_or_else(|| {
                                state_error(
                                    ErrorCode::FailedPrecondition,
                                    "load-container-state",
                                    format!(
                                        "container {id} shared-guest isolation has no durable guest-session attachment"
                                    ),
                                )
                            })?
                            .trust_domain()
                            .clone(),
                    },
                };
                attachments.validate_isolation(&isolation).map_err(|error| {
                    state_error(
                        ErrorCode::FailedPrecondition,
                        "load-container-state",
                        format!(
                            "container {id} guest-session evidence or TEE launch evidence does not match its durable isolation: {}",
                            error.message
                        ),
                    )
                })?;
                let expected_network_enforcement = attachments.network_enforcement(&bundle)?;
                if (stored.record.guest_session.is_some()
                    && stored.record.isolation != IsolationClass::SharedGuestKernel)
                    || stored.record.guest_session.as_ref() != attachments.guest_session()
                    || stored.record.network_enforcement.as_ref()
                        != expected_network_enforcement.as_ref()
                {
                    return Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "load-container-state",
                        format!(
                            "container {id} guest-session evidence or network-enforcement evidence does not match its durable attachment contract"
                        ),
                    ));
                }
                if attachments.digest()? != *expected_digest {
                    return Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "load-container-state",
                        format!(
                            "container {id} attachment digest does not match its durable contract"
                        ),
                    ));
                }
            }
            (None, None)
                if stored.record.guest_session.is_none()
                    && stored.record.network_enforcement.is_none() => {}
            _ => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "load-container-state",
                    format!("container {id} has incomplete durable attachment evidence"),
                ));
            }
        }
        Ok(stored)
    }

    async fn load_bundle(&self, stored: &StoredContainer) -> Result<OciBundle> {
        let directory = self.container_directory(&stored.id);
        self.load_bundle_from_directory(stored, &directory).await
    }

    async fn load_bundle_from_directory(
        &self,
        stored: &StoredContainer,
        directory: &Path,
    ) -> Result<OciBundle> {
        let config_path = directory.join(CONFIG_SNAPSHOT_FILE);
        if !self.filesystem.path_exists(&config_path).await? {
            return Err(state_error(
                ErrorCode::Unavailable,
                "load-durable-bundle",
                format!("container {} has no configuration snapshot", stored.id),
            )
            .retryable(true));
        }
        let config_json = self.filesystem.read_utf8(&config_path).await?;
        OciBundle::from_json(stored.record.state.bundle().clone(), config_json)
    }

    fn container_directory(&self, id: &ContainerId) -> PathBuf {
        self.root.join("containers").join(id.as_str())
    }

    fn generation_path(&self, id: &ContainerId) -> PathBuf {
        self.root
            .join("generations")
            .join(format!("{}.json", id.as_str()))
    }

    fn operation_path(&self, id: &OperationId) -> PathBuf {
        self.root
            .join("operations")
            .join(format!("{}.json", id.as_str()))
    }

    fn process_directory(&self, id: &ContainerId) -> PathBuf {
        self.container_directory(id).join("processes")
    }

    fn process_path(&self, target: &ProcessTarget) -> PathBuf {
        self.process_directory(&target.container.id)
            .join(format!("{}.json", target.process_id.as_str()))
    }

    fn failed_create_tombstone(&self, operation_id: &OperationId) -> PathBuf {
        self.root
            .join("quarantine")
            .join(format!("{}.failed-create", operation_id.as_str()))
    }

    fn failed_restore_tombstone(&self, operation_id: &OperationId) -> PathBuf {
        self.root
            .join("quarantine")
            .join(format!("{}.failed-restore", operation_id.as_str()))
    }

    async fn write_json(
        &self,
        mutation: DurableMutation,
        path: &Path,
        value: &impl serde::Serialize,
    ) -> Result<()> {
        self.filesystem
            .atomic_write_json(self.faults.as_ref(), mutation, path, value)
            .await
    }

    async fn write_bytes(
        &self,
        mutation: DurableMutation,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        self.filesystem
            .atomic_write(self.faults.as_ref(), mutation, path, bytes)
            .await
    }

    async fn move_directory(
        &self,
        mutation: DurableMutation,
        source: &Path,
        destination: &Path,
    ) -> Result<()> {
        self.filesystem
            .atomic_move_directory(self.faults.as_ref(), mutation, source, destination)
            .await
    }
}

fn validate_stored_operation_shape(operation: &StoredOperation) -> Result<()> {
    let invalid = |message: String| {
        state_error(
            ErrorCode::FailedPrecondition,
            "load-operation",
            format!(
                "invalid durable operation record for {}: {message}",
                operation.operation_id
            ),
        )
    };
    let request_target_matches = |target: &ContainerTarget| {
        target.id == operation.container_id
            && target
                .generation
                .is_none_or(|generation| generation == operation.generation)
    };
    let response_target_matches = |target: &ContainerTarget| {
        target.id == operation.container_id && target.generation == Some(operation.generation)
    };

    match operation.kind {
        StoredOperationKind::File => {
            if !matches!(
                operation.schema_version.as_str(),
                OPERATION_SCHEMA_VERSION_V3
                    | OPERATION_SCHEMA_VERSION_V4
                    | OPERATION_SCHEMA_VERSION_V5
                    | OPERATION_SCHEMA_VERSION
            ) {
                return Err(invalid(
                    "File mutations require the current request-retaining schema".to_string(),
                ));
            }
            let Some(StoredOperationRequest::File(request)) = operation.request.as_ref() else {
                return Err(invalid(
                    "File mutation does not retain its exact request".to_string(),
                ));
            };
            if request.op != FileOp::Upload
                || !request_target_matches(&request.target)
                || request
                    .context
                    .as_ref()
                    .is_none_or(|context| context.operation_id != operation.operation_id)
                || request.validate().is_err()
            {
                return Err(invalid(
                    "File mutation request does not match its durable identity".to_string(),
                ));
            }
            match &operation.outcome {
                StoredOperationStatus::Prepared | StoredOperationStatus::Failed { .. } => {}
                StoredOperationStatus::SucceededFilesystem { response } => {
                    let StoredFilesystemMutationResponse::File(response) = response else {
                        return Err(invalid(
                            "File mutation contains a Filesystem response".to_string(),
                        ));
                    };
                    if !response_target_matches(&response.target) {
                        return Err(invalid(
                            "File response targets a different container generation".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(invalid(
                        "File mutation contains an incompatible outcome".to_string(),
                    ));
                }
            }
        }
        StoredOperationKind::Filesystem => {
            if !matches!(
                operation.schema_version.as_str(),
                OPERATION_SCHEMA_VERSION_V3
                    | OPERATION_SCHEMA_VERSION_V4
                    | OPERATION_SCHEMA_VERSION_V5
                    | OPERATION_SCHEMA_VERSION
            ) {
                return Err(invalid(
                    "Filesystem mutations require the current request-retaining schema".to_string(),
                ));
            }
            let Some(StoredOperationRequest::Filesystem(request)) = operation.request.as_ref()
            else {
                return Err(invalid(
                    "Filesystem mutation does not retain its exact request".to_string(),
                ));
            };
            if !request.op.is_mutating()
                || !request_target_matches(&request.target)
                || request
                    .context
                    .as_ref()
                    .is_none_or(|context| context.operation_id != operation.operation_id)
                || request.validate().is_err()
            {
                return Err(invalid(
                    "Filesystem mutation request does not match its durable identity".to_string(),
                ));
            }
            match &operation.outcome {
                StoredOperationStatus::Prepared | StoredOperationStatus::Failed { .. } => {}
                StoredOperationStatus::SucceededFilesystem { response } => {
                    let StoredFilesystemMutationResponse::Filesystem(response) = response else {
                        return Err(invalid(
                            "Filesystem mutation contains a File response".to_string(),
                        ));
                    };
                    if !response_target_matches(&response.target) {
                        return Err(invalid(
                            "Filesystem response targets a different container generation"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(invalid(
                        "Filesystem mutation contains an incompatible outcome".to_string(),
                    ));
                }
            }
        }
        StoredOperationKind::Checkpoint => {
            if !matches!(
                operation.schema_version.as_str(),
                OPERATION_SCHEMA_VERSION_V4
                    | OPERATION_SCHEMA_VERSION_V5
                    | OPERATION_SCHEMA_VERSION
            ) {
                return Err(invalid(
                    "Checkpoint mutations require the current request-retaining schema".to_string(),
                ));
            }
            let Some(StoredOperationRequest::Checkpoint(request)) = operation.request.as_ref()
            else {
                return Err(invalid(
                    "Checkpoint mutation does not retain its exact request".to_string(),
                ));
            };
            let request_digest_matches = checkpoint::checkpoint_request_digest(request)
                .is_ok_and(|digest| digest.current() == operation.request_digest);
            if !request_target_matches(request.target())
                || request.context().operation_id != operation.operation_id
                || request.validate().is_err()
                || !request_digest_matches
            {
                return Err(invalid(
                    "Checkpoint request does not match its durable identity".to_string(),
                ));
            }
            match &operation.outcome {
                StoredOperationStatus::Prepared | StoredOperationStatus::Failed { .. } => {}
                StoredOperationStatus::SucceededCheckpoint { response } => {
                    if response.validate_for_request(request).is_err() {
                        return Err(invalid(
                            "Checkpoint response does not match its retained request".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(invalid(
                        "Checkpoint mutation contains an incompatible outcome".to_string(),
                    ));
                }
            }
        }
        StoredOperationKind::Restore => {
            if !matches!(
                operation.schema_version.as_str(),
                OPERATION_SCHEMA_VERSION_V5 | OPERATION_SCHEMA_VERSION
            ) {
                return Err(invalid(
                    "Restore mutations require the current request-retaining schema".to_string(),
                ));
            }
            let Some(StoredOperationRequest::Restore(request)) = operation.request.as_ref() else {
                return Err(invalid(
                    "Restore mutation does not retain its exact request".to_string(),
                ));
            };
            let request_digest_matches = restore::restore_request_digest(request)
                .is_ok_and(|digest| digest.current() == operation.request_digest);
            if request.id() != &operation.container_id
                || request.context().operation_id != operation.operation_id
                || request.validate().is_err()
                || !request_digest_matches
            {
                return Err(invalid(
                    "Restore request does not match its durable identity".to_string(),
                ));
            }
            match &operation.outcome {
                StoredOperationStatus::Prepared | StoredOperationStatus::Failed { .. } => {}
                StoredOperationStatus::SucceededRestore { response } => {
                    if response.restored().generation != operation.generation
                        || response.validate_for_request(request).is_err()
                    {
                        return Err(invalid(
                            "Restore response does not match its retained request and generation"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(invalid(
                        "Restore mutation contains an incompatible outcome".to_string(),
                    ));
                }
            }
        }
        StoredOperationKind::Attest => {
            if operation.schema_version != OPERATION_SCHEMA_VERSION {
                return Err(invalid(
                    "TEE attestation mutations require operation schema v6".to_string(),
                ));
            }
            let Some(StoredOperationRequest::Attest(request)) = operation.request.as_ref() else {
                return Err(invalid(
                    "TEE attestation mutation does not retain its exact request".to_string(),
                ));
            };
            let request_digest_matches = attestation::attestation_request_digest(request)
                .is_ok_and(|digest| digest.current() == operation.request_digest);
            if !response_target_matches(&request.target)
                || request.context.operation_id != operation.operation_id
                || request.validate().is_err()
                || !request_digest_matches
            {
                return Err(invalid(
                    "TEE attestation request does not match its durable identity".to_string(),
                ));
            }
            match &operation.outcome {
                StoredOperationStatus::Prepared | StoredOperationStatus::Failed { .. } => {}
                StoredOperationStatus::SucceededAttestation { response } => {
                    if response.validate_for_request(request).is_err() {
                        return Err(invalid(
                            "TEE attestation response does not match its retained request"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(invalid(
                        "TEE attestation mutation contains an incompatible outcome".to_string(),
                    ));
                }
            }
        }
        StoredOperationKind::Create
        | StoredOperationKind::Start
        | StoredOperationKind::Kill
        | StoredOperationKind::Delete
        | StoredOperationKind::Exec
        | StoredOperationKind::SignalProcess
        | StoredOperationKind::WriteStdin
        | StoredOperationKind::CloseStdin
        | StoredOperationKind::Resize
        | StoredOperationKind::Pause
        | StoredOperationKind::Resume
        | StoredOperationKind::Update => {
            if operation.request.is_some()
                || matches!(
                    operation.outcome,
                    StoredOperationStatus::SucceededFilesystem { .. }
                        | StoredOperationStatus::SucceededCheckpoint { .. }
                        | StoredOperationStatus::SucceededRestore { .. }
                        | StoredOperationStatus::SucceededAttestation { .. }
                )
            {
                return Err(invalid(
                    "non-filesystem operation contains filesystem mutation data".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn generation_conflict(
    id: &ContainerId,
    expected: Generation,
    actual: Generation,
    operation: &'static str,
) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::Conflict,
        operation,
        format!(
            "container {id} generation mismatch: expected {}, current {}",
            expected.0, actual.0
        ),
    )
}

fn ensure_active_operation(
    stored: &StoredContainer,
    operation_id: &OperationId,
    operation: &'static str,
) -> Result<()> {
    match stored.active_operation.as_ref() {
        Some(active) if active == operation_id => Ok(()),
        Some(active) => Err(state_error(
            ErrorCode::Conflict,
            operation,
            format!(
                "container {} is owned by active operation {active}, not {operation_id}",
                stored.id
            ),
        )),
        None => Ok(()),
    }
}

async fn claim_active_operation(
    store: &DurableStateStore,
    stored: &mut StoredContainer,
    operation_id: &OperationId,
    mutation: DurableMutation,
    operation: &'static str,
) -> Result<()> {
    if stored.active_operation.as_ref() == Some(operation_id) {
        return Ok(());
    }
    if let Some(active) = stored.active_operation.clone() {
        if process_io::migrate_legacy_init_io_claim(store, stored)
            .await?
            .is_none()
        {
            return Err(state_error(
                ErrorCode::Conflict,
                operation,
                format!(
                    "container {} already has active operation {active}",
                    stored.id
                ),
            ));
        }
        if matches!(
            mutation,
            DurableMutation::ClaimDeleteOperation | DurableMutation::ClaimCheckpointOperation
        ) {
            return Err(state_error(
                ErrorCode::Conflict,
                operation,
                format!(
                    "container {} init process is owned by active I/O operation {active}",
                    stored.id
                ),
            )
            .retryable(true));
        }
    }
    stored.active_operation = Some(operation_id.clone());
    store
        .write_json(
            mutation,
            &store
                .container_directory(&stored.id)
                .join(CONTAINER_RECORD_FILE),
            stored,
        )
        .await
}

#[cfg(test)]
mod tests;
