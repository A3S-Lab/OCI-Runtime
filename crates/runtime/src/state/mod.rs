mod create;
mod delete;
mod event;
mod failure;
mod filesystem;
mod freezer;
mod kill;
mod list;
mod model;
mod observe;
mod oci_state;
mod operation;
mod process;
mod process_io;
mod start;
mod update;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_core::{DriverKind, LifecycleEvent, LifecycleState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerRecord, ContainerTarget, CreateRequest, ErrorCode, Generation, OciBundle,
    OciSchemaValidator, OperationId, ProcessRecord, ProcessTarget, Result, RuntimeEventKind,
    ValidateRequest,
};
use tokio::sync::{Mutex, Notify};

#[cfg(test)]
use crate::fault::NoFaultInjector;
use crate::fault::{DurableMutation, FaultInjector};

use create::{create_request_digest, validate_create_retry};
use filesystem::{
    create_private_directory, ensure_plain_directory, path_exists, read_json, read_utf8,
    state_error, RootLock,
};
use model::{
    StoredContainer, StoredGeneration, StoredOperation, StoredOperationKind, StoredOperationStatus,
    CONTAINER_SCHEMA_VERSION, GENERATION_SCHEMA_VERSION, OPERATION_SCHEMA_VERSION,
};
use oci_state::{build_state, container_state, is_paused, rebuild_state};
use operation::validate_deadline;

const CONTAINER_RECORD_FILE: &str = "record.json";
const CONFIG_SNAPSHOT_FILE: &str = "config.json";

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

/// Single-writer durable lifecycle store.
#[derive(Debug, Clone)]
pub(crate) struct DurableStateStore {
    root: Arc<PathBuf>,
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
        let (root, root_lock) = filesystem::open_root(root.as_ref(), faults.as_ref()).await?;
        Ok(Self {
            root: Arc::new(root),
            gate: Arc::new(Mutex::new(())),
            event_notify: Arc::new(Notify::new()),
            _root_lock: root_lock,
            faults,
        })
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
        if path_exists(&container_directory).await? {
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
            request_digest,
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
        let attachments_digest = request.attachments.digest()?;
        let container_directory = self.container_directory(&request.id);
        if path_exists(&container_directory).await? {
            ensure_plain_directory(&container_directory, "container state directory").await?;
            filesystem::set_private_directory_permissions(&container_directory).await?;
        } else {
            create_private_directory(&container_directory).await?;
        }

        let config_path = container_directory.join(CONFIG_SNAPSHOT_FILE);
        if path_exists(&config_path).await? {
            let durable_config = read_utf8(&config_path).await?;
            if durable_config.as_bytes() != request.bundle.config_bytes() {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "reconcile-create",
                    format!(
                        "container {} configuration snapshot differs from its create request",
                        request.id
                    ),
                ));
            }
        } else {
            self.write_bytes(
                DurableMutation::StoreCreateConfig,
                &config_path,
                request.bundle.config_bytes(),
            )
            .await?;
        }

        let record_path = container_directory.join(CONTAINER_RECORD_FILE);
        if path_exists(&record_path).await? {
            let stored = self.load_stored_exact(&request.id, generation).await?;
            if stored.record.driver != driver
                || stored.record.isolation != request.isolation.class()
                || stored.record.config_digest != request.bundle.config_digest()
                || stored.record.attachments_digest.as_deref() != Some(attachments_digest.as_str())
                || stored.attachments.as_ref() != Some(&request.attachments)
            {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "reconcile-create",
                    format!(
                        "container {} durable record differs from its create request",
                        request.id
                    ),
                ));
            }
            return Ok(stored);
        }

        let state = build_state(&request.id, &request.bundle, ContainerState::Creating, None)?;
        let record = ContainerRecord {
            state,
            generation,
            driver,
            isolation: request.isolation.class(),
            config_digest: request.bundle.config_digest().to_string(),
            attachments_digest: Some(attachments_digest),
        };
        let stored = StoredContainer {
            schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
            id: request.id.clone(),
            record,
            attachments: Some(request.attachments.clone()),
            active_operation: Some(request.context.operation_id.clone()),
            init_exit_status: None,
        };
        self.write_json(
            DurableMutation::StoreCreatingContainer,
            &record_path,
            &stored,
        )
        .await?;
        Ok(stored)
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
                active.kind == StoredOperationKind::Start
                    && active.container_id == stored.id
                    && active.generation == stored.record.generation
                    && matches!(active.outcome, StoredOperationStatus::Prepared)
                    && durable_status == ContainerState::Created
            }
            None => true,
        };
        if !active_allows_rebind
            || *response.state.status() != ContainerState::Created
            || is_paused(&stored.record.state)
        {
            return Err(state_error(
                ErrorCode::Conflict,
                "reconcile-succeeded-create",
                format!(
                    "completed create operation {} differs from its durable container record",
                    operation.operation_id
                ),
            ));
        }
        let expected_durable = ContainerRecord {
            state: rebuild_state(&response.state, durable_status, *stored.record.state.pid())?,
            ..response.clone()
        };
        if expected_durable != stored.record {
            return Err(state_error(
                ErrorCode::Conflict,
                "reconcile-succeeded-create",
                format!(
                    "completed create operation {} changed beyond its recovered process identity",
                    operation.operation_id
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

    async fn next_generation(&self, id: &ContainerId) -> Result<Generation> {
        let path = self.generation_path(id);
        let last = if path_exists(&path).await? {
            let stored: StoredGeneration = read_json(&path).await?;
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
        if !path_exists(&path).await? {
            return Ok(None);
        }
        self.load_operation(operation_id).await.map(Some)
    }

    async fn load_operation(&self, operation_id: &OperationId) -> Result<StoredOperation> {
        let path = self.operation_path(operation_id);
        if !path_exists(&path).await? {
            return Err(state_error(
                ErrorCode::NotFound,
                "load-operation",
                format!("operation {operation_id} does not exist"),
            ));
        }
        let operation: StoredOperation = read_json(&path).await?;
        if operation.schema_version != OPERATION_SCHEMA_VERSION
            || operation.operation_id != *operation_id
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-operation",
                format!("invalid durable operation record for {operation_id}"),
            ));
        }
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
        if !path_exists(&directory).await? {
            return Err(state_error(
                ErrorCode::NotFound,
                "load-container-state",
                format!("container {id} does not exist"),
            ));
        }
        ensure_plain_directory(&directory, "container state directory").await?;
        filesystem::set_private_directory_permissions(&directory).await?;
        let path = directory.join(CONTAINER_RECORD_FILE);
        if !path_exists(&path).await? {
            return Err(state_error(
                ErrorCode::Unavailable,
                "reconcile-container-state",
                format!("container {id} has no durable record"),
            )
            .retryable(true));
        }
        let stored: StoredContainer = read_json(&path).await?;
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
        let bundle = self.load_bundle(&stored).await?;
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
            (None, None) => {}
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
        let config_path = self
            .container_directory(&stored.id)
            .join(CONFIG_SNAPSHOT_FILE);
        if !path_exists(&config_path).await? {
            return Err(state_error(
                ErrorCode::Unavailable,
                "load-durable-bundle",
                format!("container {} has no configuration snapshot", stored.id),
            )
            .retryable(true));
        }
        let config_json = read_utf8(&config_path).await?;
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

    async fn write_json(
        &self,
        mutation: DurableMutation,
        path: &Path,
        value: &impl serde::Serialize,
    ) -> Result<()> {
        filesystem::atomic_write_json(self.faults.as_ref(), mutation, path, value).await
    }

    async fn write_bytes(
        &self,
        mutation: DurableMutation,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        filesystem::atomic_write(self.faults.as_ref(), mutation, path, bytes).await
    }

    async fn move_directory(
        &self,
        mutation: DurableMutation,
        source: &Path,
        destination: &Path,
    ) -> Result<()> {
        filesystem::atomic_move_directory(self.faults.as_ref(), mutation, source, destination).await
    }
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
    match stored.active_operation.as_ref() {
        Some(active) if active == operation_id => return Ok(()),
        Some(active) => {
            return Err(state_error(
                ErrorCode::Conflict,
                operation,
                format!(
                    "container {} already has active operation {active}",
                    stored.id
                ),
            ));
        }
        None => stored.active_operation = Some(operation_id.clone()),
    }
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
