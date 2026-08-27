use a3s_oci_sdk::Result;

use super::{audit_error, entry_name, parse_operation_id, OperationInventory};
use crate::state::model::{StoredOperationKind, StoredOperationStatus};
use crate::state::DurableStateStore;

impl DurableStateStore {
    pub(super) async fn audit_quarantine_entries(
        &self,
        operations: &OperationInventory,
    ) -> Result<()> {
        let directory = self.root.join("quarantine");
        for entry in self
            .filesystem
            .read_directory(&directory, "quarantine state directory")
            .await?
        {
            let name = entry_name(
                entry,
                "audit-quarantine-state",
                "quarantine state directory",
            )?;
            let (stem, expected_kind, failed_creation) =
                if let Some(stem) = name.strip_suffix(".deleted") {
                    (stem, StoredOperationKind::Delete, false)
                } else if let Some(stem) = name.strip_suffix(".failed-create") {
                    (stem, StoredOperationKind::Create, true)
                } else if let Some(stem) = name.strip_suffix(".failed-restore") {
                    (stem, StoredOperationKind::Restore, true)
                } else {
                    return Err(audit_error(
                        "audit-quarantine-state",
                        format!("quarantine contains unexpected entry {name:?}"),
                    ));
                };
            let operation_id = parse_operation_id(stem, "audit-quarantine-state", &name)?;
            let operation = operations.get(operation_id.as_str()).ok_or_else(|| {
                audit_error(
                    "audit-quarantine-state",
                    format!("quarantine entry {name:?} has no durable operation"),
                )
            })?;
            let valid_outcome = if failed_creation {
                matches!(operation.outcome, StoredOperationStatus::Failed { .. })
            } else {
                matches!(
                    operation.outcome,
                    StoredOperationStatus::Prepared | StoredOperationStatus::SucceededEmpty
                )
            };
            if operation.kind != expected_kind || !valid_outcome {
                return Err(audit_error(
                    "audit-quarantine-state",
                    format!("quarantine entry {name:?} disagrees with its durable operation"),
                ));
            }

            let entry_path = directory.join(&name);
            self.filesystem
                .ensure_plain_directory(&entry_path, "quarantine state entry")
                .await?;
            if !self
                .audit_container_layout(&entry_path, &operation.container_id)
                .await?
            {
                return Err(audit_error(
                    "audit-quarantine-state",
                    format!("quarantine entry {name:?} has no durable container record"),
                ));
            }
            let stored = self
                .load_stored_container_from_directory(&operation.container_id, &entry_path)
                .await
                .map_err(|error| {
                    audit_error(
                        "audit-quarantine-state",
                        format!("invalid quarantine entry {name:?}: {error}"),
                    )
                })?;
            if stored.record.generation != operation.generation
                || stored.active_operation.as_ref() != Some(&operation.operation_id)
                || !stored.init_io_operations.is_empty()
            {
                return Err(audit_error(
                    "audit-quarantine-state",
                    format!("quarantine entry {name:?} disagrees with its durable operation"),
                ));
            }
            let live_directory = self.container_directory(&operation.container_id);
            if self.filesystem.path_exists(&live_directory).await? {
                let live = self.load_stored_container(&operation.container_id).await?;
                if live.record.generation == operation.generation {
                    return Err(audit_error(
                        "audit-quarantine-state",
                        format!(
                            "container {} generation {} is both live and quarantined",
                            operation.container_id, operation.generation.0
                        ),
                    ));
                }
            }
            self.audit_process_entries(&stored, &entry_path, operations, false)
                .await?;
        }
        Ok(())
    }
}
