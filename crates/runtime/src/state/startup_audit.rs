use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;

use a3s_oci_sdk::{
    ContainerId, ContainerTarget, ErrorCode, Generation, OperationId, ProcessId, ProcessTarget,
    Result,
};

use super::filesystem::state_error;
use super::model::{
    StoredContainer, StoredGeneration, StoredOperation, StoredOperationKind,
    StoredOperationRequest, StoredOperationStatus, GENERATION_SCHEMA_VERSION,
};
use super::{DurableStateStore, CONFIG_SNAPSHOT_FILE, CONTAINER_RECORD_FILE};

mod event;
mod quarantine;

type OperationInventory = BTreeMap<String, StoredOperation>;
type GenerationInventory = BTreeMap<String, Generation>;

impl DurableStateStore {
    pub(super) async fn audit_startup_state(&self) -> Result<()> {
        self.audit_root_entries().await?;
        let operations = self.audit_operation_entries().await?;
        let generations = self.audit_generation_entries().await?;
        self.audit_operation_generations(&operations, &generations)?;
        self.audit_container_entries(&operations, &generations)
            .await?;
        self.audit_quarantine_entries(&operations).await?;
        self.audit_event_entries().await
    }

    async fn audit_root_entries(&self) -> Result<()> {
        for entry in self
            .filesystem
            .read_directory(self.root.as_ref(), "runtime state root")
            .await?
        {
            let name = entry_name(entry, "audit-state-root", "runtime state root")?;
            let path = self.root.join(&name);
            match name.as_str() {
                ".lock" | "root.json" | ".root.json.next" => {
                    self.filesystem
                        .ensure_plain_file(&path, "runtime state root file")
                        .await?;
                }
                "containers" | "generations" | "operations" | "quarantine" | "events" => {
                    self.filesystem
                        .ensure_plain_directory(&path, "runtime state layout directory")
                        .await?;
                }
                _ => {
                    return Err(audit_error(
                        "audit-state-root",
                        format!("runtime state root contains unexpected entry {name:?}"),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn audit_generation_entries(&self) -> Result<GenerationInventory> {
        let directory = self.root.join("generations");
        let mut inventory = BTreeMap::new();
        for entry in self
            .filesystem
            .read_directory(&directory, "generation state directory")
            .await?
        {
            let name = entry_name(
                entry,
                "audit-generation-state",
                "generation state directory",
            )?;
            if let Some(stem) = transaction_stem(&name) {
                parse_container_id(stem, "audit-generation-state", &name)?;
                self.filesystem
                    .ensure_plain_file(&directory.join(&name), "generation state transaction file")
                    .await?;
                continue;
            }
            let stem = json_stem(&name, "audit-generation-state", "generation record")?;
            let id = parse_container_id(stem, "audit-generation-state", &name)?;
            let stored: StoredGeneration =
                self.filesystem.read_json(&directory.join(&name)).await?;
            if stored.schema_version != GENERATION_SCHEMA_VERSION
                || stored.id != id
                || stored.last_generation.0 == 0
            {
                return Err(audit_error(
                    "audit-generation-state",
                    format!("invalid durable generation record {name:?}"),
                ));
            }
            inventory.insert(id.as_str().to_string(), stored.last_generation);
        }
        Ok(inventory)
    }

    async fn audit_operation_entries(&self) -> Result<OperationInventory> {
        let directory = self.root.join("operations");
        let mut inventory = BTreeMap::new();
        for entry in self
            .filesystem
            .read_directory(&directory, "operation state directory")
            .await?
        {
            let name = entry_name(entry, "audit-operation-state", "operation state directory")?;
            if let Some(stem) = transaction_stem(&name) {
                parse_operation_id(stem, "audit-operation-state", &name)?;
                self.filesystem
                    .ensure_plain_file(&directory.join(&name), "operation state transaction file")
                    .await?;
                continue;
            }
            let stem = json_stem(&name, "audit-operation-state", "operation record")?;
            let id = parse_operation_id(stem, "audit-operation-state", &name)?;
            let operation = self.load_operation(&id).await?;
            inventory.insert(id.as_str().to_string(), operation);
        }
        Ok(inventory)
    }

    fn audit_operation_generations(
        &self,
        operations: &OperationInventory,
        generations: &GenerationInventory,
    ) -> Result<()> {
        let mut creation_owners = BTreeSet::new();
        for operation in operations.values() {
            let last_generation = generations
                .get(operation.container_id.as_str())
                .ok_or_else(|| {
                    audit_error(
                        "audit-operation-state",
                        format!(
                            "operation {} references container {} without a generation record",
                            operation.operation_id, operation.container_id
                        ),
                    )
                })?;
            if operation.generation.0 == 0 || operation.generation.0 > last_generation.0 {
                return Err(audit_error(
                    "audit-operation-state",
                    format!(
                        "operation {} generation {} exceeds container {} generation {}",
                        operation.operation_id,
                        operation.generation.0,
                        operation.container_id,
                        last_generation.0
                    ),
                ));
            }
            if matches!(
                operation.kind,
                StoredOperationKind::Create | StoredOperationKind::Restore
            ) && !creation_owners.insert((
                operation.container_id.as_str().to_string(),
                operation.generation.0,
            )) {
                return Err(audit_error(
                    "audit-operation-state",
                    format!(
                        "container {} generation {} has more than one creation operation",
                        operation.container_id, operation.generation.0
                    ),
                ));
            }
        }
        Ok(())
    }

    async fn audit_container_entries(
        &self,
        operations: &OperationInventory,
        generations: &GenerationInventory,
    ) -> Result<()> {
        let directory = self.root.join("containers");
        for entry in self
            .filesystem
            .read_directory(&directory, "container state root")
            .await?
        {
            let name = entry_name(entry, "audit-container-state", "container state root")?;
            let id = parse_container_id(&name, "audit-container-state", &name)?;
            let container_directory = directory.join(&name);
            self.filesystem
                .ensure_plain_directory(&container_directory, "container state directory")
                .await?;
            self.filesystem
                .set_private_directory_permissions(&container_directory)
                .await?;
            let has_record = self
                .audit_container_layout(&container_directory, &id)
                .await?;
            if !has_record {
                let prepared = generations.get(id.as_str()).is_some_and(|last_generation| {
                    operations.values().any(|operation| {
                        matches!(
                            operation.kind,
                            StoredOperationKind::Create | StoredOperationKind::Restore
                        ) && operation.container_id == id
                            && operation.generation == *last_generation
                            && matches!(operation.outcome, StoredOperationStatus::Prepared)
                    })
                });
                if !prepared {
                    return Err(audit_error(
                        "audit-container-state",
                        format!(
                            "container state directory {name:?} has no record or prepared creation operation"
                        ),
                    ));
                }
                continue;
            }

            let stored = self.load_stored_container(&id).await?;
            let Some(last_generation) = generations.get(id.as_str()) else {
                return Err(audit_error(
                    "audit-container-state",
                    format!("container {id} has no durable generation record"),
                ));
            };
            if stored.record.generation != *last_generation {
                return Err(audit_error(
                    "audit-container-state",
                    format!(
                        "container {id} generation {} disagrees with durable generation {}",
                        stored.record.generation.0, last_generation.0
                    ),
                ));
            }
            let has_creation = operations.values().any(|operation| {
                matches!(
                    operation.kind,
                    StoredOperationKind::Create | StoredOperationKind::Restore
                ) && operation.container_id == id
                    && operation.generation == stored.record.generation
            });
            if !has_creation {
                return Err(audit_error(
                    "audit-container-state",
                    format!(
                        "container {id} generation {} has no durable creation operation",
                        stored.record.generation.0
                    ),
                ));
            }
            self.audit_attestation_outcomes(&stored, operations).await?;
            self.audit_container_claims(&stored, operations)?;
            self.audit_process_entries(&stored, &container_directory, operations, true)
                .await?;
        }
        Ok(())
    }

    async fn audit_attestation_outcomes(
        &self,
        stored: &StoredContainer,
        operations: &OperationInventory,
    ) -> Result<()> {
        for operation in operations.values().filter(|operation| {
            operation.kind == StoredOperationKind::Attest
                && operation.container_id == stored.id
                && operation.generation == stored.record.generation
        }) {
            let StoredOperationStatus::SucceededAttestation { response } = &operation.outcome
            else {
                continue;
            };
            let Some(StoredOperationRequest::Attest(request)) = operation.request.as_ref() else {
                return Err(audit_error(
                    "audit-operation-state",
                    format!(
                        "TEE attestation operation {} has no retained request",
                        operation.operation_id
                    ),
                ));
            };
            let source = self
                .validate_attestation_bindings(stored)
                .await
                .map_err(|error| {
                    audit_error(
                        "audit-operation-state",
                        format!(
                            "TEE attestation operation {} has an invalid durable source: {}",
                            operation.operation_id, error.message
                        ),
                    )
                })?;
            super::attestation::validate_attestation_response_bindings(
                &source,
                &operation.operation_id,
                request,
                response,
            )
            .map_err(|error| {
                audit_error(
                    "audit-operation-state",
                    format!(
                        "TEE attestation operation {} has invalid durable evidence: {}",
                        operation.operation_id, error.message
                    ),
                )
            })?;
        }
        Ok(())
    }

    async fn audit_container_layout(&self, directory: &Path, id: &ContainerId) -> Result<bool> {
        let mut has_record = false;
        let mut has_processes = false;
        for entry in self
            .filesystem
            .read_directory(directory, "container state directory")
            .await?
        {
            let name = entry_name(entry, "audit-container-state", "container state directory")?;
            let path = directory.join(&name);
            match name.as_str() {
                CONTAINER_RECORD_FILE | CONFIG_SNAPSHOT_FILE => {
                    self.filesystem
                        .ensure_plain_file(&path, "container state file")
                        .await?;
                    has_record |= name == CONTAINER_RECORD_FILE;
                }
                ".record.json.next" | ".config.json.next" => {
                    self.filesystem
                        .ensure_plain_file(&path, "container state transaction file")
                        .await?;
                }
                "processes" => {
                    self.filesystem
                        .ensure_plain_directory(&path, "process state directory")
                        .await?;
                    has_processes = true;
                }
                _ => {
                    return Err(audit_error(
                        "audit-container-state",
                        format!("container {id} contains unexpected state entry {name:?}"),
                    ));
                }
            }
        }
        if has_processes && !has_record {
            return Err(audit_error(
                "audit-container-state",
                format!("container {id} has process state without a container record"),
            ));
        }
        Ok(has_record)
    }

    fn audit_container_claims(
        &self,
        stored: &super::model::StoredContainer,
        operations: &OperationInventory,
    ) -> Result<()> {
        if let Some(operation_id) = &stored.active_operation {
            validate_claim(
                operations,
                operation_id,
                &stored.id,
                stored.record.generation,
                None,
                "container",
            )?;
        }
        for operation_id in &stored.init_io_operations {
            validate_claim(
                operations,
                operation_id,
                &stored.id,
                stored.record.generation,
                Some(&ProcessId::init()),
                "init process I/O",
            )?;
        }
        Ok(())
    }

    async fn audit_process_entries(
        &self,
        container: &super::model::StoredContainer,
        container_directory: &Path,
        operations: &OperationInventory,
        allow_active_claims: bool,
    ) -> Result<()> {
        let directory = container_directory.join("processes");
        if !self.filesystem.path_exists(&directory).await? {
            return Ok(());
        }
        for entry in self
            .filesystem
            .read_directory(&directory, "process state directory")
            .await?
        {
            let name = entry_name(entry, "audit-process-state", "process state directory")?;
            if let Some(stem) = transaction_stem(&name) {
                parse_process_id(stem, "audit-process-state", &name)?;
                self.filesystem
                    .ensure_plain_file(&directory.join(&name), "process state transaction file")
                    .await?;
                continue;
            }
            let stem = json_stem(&name, "audit-process-state", "process record")?;
            let process_id = parse_process_id(stem, "audit-process-state", &name)?;
            if process_id.is_init() {
                return Err(audit_error(
                    "audit-process-state",
                    "init process state must remain in the container record",
                ));
            }
            let target = ProcessTarget {
                container: ContainerTarget::exact(
                    container.id.clone(),
                    container.record.generation,
                ),
                process_id: process_id.clone(),
            };
            let process = self
                .load_stored_process_from_path(&target, &directory.join(&name))
                .await?;
            if !allow_active_claims
                && (process.active_operation.is_some() || !process.active_io_operations.is_empty())
            {
                return Err(audit_error(
                    "audit-process-state",
                    format!("quarantined process {process_id} retains an active operation claim"),
                ));
            }
            let has_exec = operations.values().any(|operation| {
                operation.kind == StoredOperationKind::Exec
                    && operation.container_id == container.id
                    && operation.generation == container.record.generation
                    && operation.process_id.as_ref() == Some(&process_id)
            });
            if !has_exec {
                return Err(audit_error(
                    "audit-process-state",
                    format!("process {process_id} has no durable Exec operation"),
                ));
            }
            if let Some(operation_id) = &process.active_operation {
                validate_claim(
                    operations,
                    operation_id,
                    &container.id,
                    container.record.generation,
                    Some(&process_id),
                    "process",
                )?;
            }
            for operation_id in &process.active_io_operations {
                validate_claim(
                    operations,
                    operation_id,
                    &container.id,
                    container.record.generation,
                    Some(&process_id),
                    "process I/O",
                )?;
            }
        }
        Ok(())
    }
}

fn validate_claim(
    operations: &OperationInventory,
    operation_id: &OperationId,
    container_id: &ContainerId,
    generation: Generation,
    process_id: Option<&ProcessId>,
    owner: &str,
) -> Result<()> {
    let operation = operations.get(operation_id.as_str()).ok_or_else(|| {
        audit_error(
            "audit-operation-claims",
            format!("{owner} references missing operation {operation_id}"),
        )
    })?;
    let recoverable_outcome = matches!(operation.outcome, StoredOperationStatus::Prepared)
        || (process_id.is_none()
            && matches!(
                operation.kind,
                StoredOperationKind::Create | StoredOperationKind::Restore
            )
            && matches!(operation.outcome, StoredOperationStatus::Failed { .. }));
    if operation.container_id != *container_id
        || operation.generation != generation
        || process_id.is_some_and(|process_id| operation.process_id.as_ref() != Some(process_id))
        || !recoverable_outcome
    {
        return Err(audit_error(
            "audit-operation-claims",
            format!("{owner} claim {operation_id} disagrees with its durable operation"),
        ));
    }
    Ok(())
}

fn entry_name(entry: OsString, operation: &'static str, label: &str) -> Result<String> {
    entry.into_string().map_err(|entry| {
        audit_error(
            operation,
            format!("{label} contains a non-UTF-8 entry: {entry:?}"),
        )
    })
}

fn json_stem<'a>(name: &'a str, operation: &'static str, label: &str) -> Result<&'a str> {
    name.strip_suffix(".json")
        .filter(|stem| !stem.is_empty())
        .ok_or_else(|| audit_error(operation, format!("invalid {label} filename {name:?}")))
}

fn transaction_stem(name: &str) -> Option<&str> {
    name.strip_prefix('.')?.strip_suffix(".json.next")
}

fn parse_container_id(value: &str, operation: &'static str, name: &str) -> Result<ContainerId> {
    ContainerId::new(value.to_string()).map_err(|error| {
        audit_error(
            operation,
            format!("invalid container state entry {name:?}: {error}"),
        )
    })
}

fn parse_operation_id(value: &str, operation: &'static str, name: &str) -> Result<OperationId> {
    OperationId::new(value.to_string()).map_err(|error| {
        audit_error(
            operation,
            format!("invalid operation state entry {name:?}: {error}"),
        )
    })
}

fn parse_process_id(value: &str, operation: &'static str, name: &str) -> Result<ProcessId> {
    ProcessId::new(value.to_string()).map_err(|error| {
        audit_error(
            operation,
            format!("invalid process state entry {name:?}: {error}"),
        )
    })
}

fn audit_error(operation: &'static str, message: impl Into<String>) -> a3s_oci_sdk::Error {
    state_error(ErrorCode::FailedPrecondition, operation, message)
}
