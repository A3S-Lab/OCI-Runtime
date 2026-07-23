mod create;
mod delete;
mod failure;
mod filesystem;
mod kill;
mod model;
mod observe;
mod oci_state;
mod operation;
mod start;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_core::{DriverKind, LifecycleEvent, LifecycleState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerRecord, ContainerTarget, CreateRequest, ErrorCode, Generation, OciBundle,
    OciSchemaValidator, OperationId, Result, ValidateRequest,
};
use tokio::sync::Mutex;

use create::{create_request_digest, validate_create_retry};
use filesystem::{
    atomic_write, atomic_write_json, create_private_directory, ensure_plain_directory, path_exists,
    read_json, read_utf8, state_error, RootLock,
};
use model::{
    StoredContainer, StoredGeneration, StoredOperation, StoredOperationKind, StoredOperationStatus,
    CONTAINER_SCHEMA_VERSION, GENERATION_SCHEMA_VERSION, OPERATION_SCHEMA_VERSION,
};
use oci_state::{build_state, container_state, rebuild_state};
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

/// Single-writer durable lifecycle store.
#[derive(Debug, Clone)]
pub(crate) struct DurableStateStore {
    root: Arc<PathBuf>,
    gate: Arc<Mutex<()>>,
    _root_lock: Arc<RootLock>,
}

impl DurableStateStore {
    /// Open or initialize one absolute runtime-owned state root.
    pub(crate) async fn open(root: impl AsRef<Path>) -> Result<Self> {
        let (root, root_lock) = filesystem::open_root(root.as_ref()).await?;
        Ok(Self {
            root: Arc::new(root),
            gate: Arc::new(Mutex::new(())),
            _root_lock: root_lock,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        self.root.as_ref()
    }

    /// Durably reserve an OCI create before invoking a driver.
    pub(crate) async fn prepare_create(
        &self,
        request: &CreateRequest,
        driver: DriverKind,
    ) -> Result<RecordOperationPreparation> {
        request.validate()?;
        let request_digest = create_request_digest(request)?;
        let _guard = self.gate.lock().await;

        if let Some(operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_create_retry(&operation, request, &request_digest)?;
            return match &operation.outcome {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .reconcile_prepared_create(request, driver, operation.generation)
                        .await?;
                    claim_active_operation(
                        self,
                        &mut stored,
                        &request.context.operation_id,
                        "prepare-create",
                    )
                    .await?;
                    Ok(RecordOperationPreparation::Resume(stored.record))
                }
                StoredOperationStatus::Succeeded { response } => {
                    Ok(RecordOperationPreparation::Replayed(response.clone()))
                }
                StoredOperationStatus::Failed { error } => {
                    self.reconcile_failed_create(&operation).await?;
                    Err(error.clone())
                }
                StoredOperationStatus::SucceededEmpty => Err(state_error(
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
            request_digest,
            outcome: StoredOperationStatus::Prepared,
        };
        atomic_write_json(
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;

        let stored = self
            .reconcile_prepared_create(request, driver, generation)
            .await?;
        let record = stored.record;
        Ok(RecordOperationPreparation::Prepared(record))
    }

    async fn reconcile_prepared_create(
        &self,
        request: &CreateRequest,
        driver: DriverKind,
        generation: Generation,
    ) -> Result<StoredContainer> {
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
            atomic_write(&config_path, request.bundle.config_bytes()).await?;
        }

        let record_path = container_directory.join(CONTAINER_RECORD_FILE);
        if path_exists(&record_path).await? {
            let stored = self.load_stored_exact(&request.id, generation).await?;
            if stored.record.driver != driver
                || stored.record.isolation != request.isolation.class()
                || stored.record.config_digest != request.bundle.config_digest()
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
        };
        let stored = StoredContainer {
            schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
            id: request.id.clone(),
            record,
            active_operation: Some(request.context.operation_id.clone()),
        };
        atomic_write_json(&record_path, &stored).await?;
        Ok(stored)
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
            StoredOperationStatus::SucceededEmpty => {
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
        atomic_write_json(
            &self
                .container_directory(&operation.container_id)
                .join(CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;
        let response = stored.record.clone();
        operation.outcome = StoredOperationStatus::Succeeded {
            response: response.clone(),
        };
        atomic_write_json(&self.operation_path(operation_id), &operation).await?;
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
        atomic_write_json(
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

    fn failed_create_tombstone(&self, operation_id: &OperationId) -> PathBuf {
        self.root
            .join("quarantine")
            .join(format!("{}.failed-create", operation_id.as_str()))
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
    atomic_write_json(
        &store
            .container_directory(&stored.id)
            .join(CONTAINER_RECORD_FILE),
        stored,
    )
    .await
}

#[cfg(test)]
mod tests;
