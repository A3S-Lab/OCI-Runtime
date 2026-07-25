use a3s_oci_sdk::{
    ContainerId, ContainerRecord, Error, ErrorCode, ListRequest, Result, ValidateRequest,
};

use super::filesystem::{ensure_plain_directory, state_error};
use super::DurableStateStore;

impl DurableStateStore {
    /// Return one deterministic snapshot of every live durable container.
    ///
    /// The store gate makes enumeration atomic with respect to lifecycle
    /// mutations in this runtime process. The exclusive runtime-root lock
    /// prevents another process from mutating the same directory concurrently.
    pub(crate) async fn list(&self, request: &ListRequest) -> Result<Vec<ContainerRecord>> {
        request.validate()?;
        let _guard = self.gate.lock().await;
        let directory = self.root.join("containers");
        ensure_plain_directory(&directory, "container state root").await?;
        let mut entries = tokio::fs::read_dir(&directory)
            .await
            .map_err(|error| list_io_error("open", &directory, error))?;
        let mut records = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| list_io_error("read", &directory, error))?
        {
            let name = entry.file_name().into_string().map_err(|name| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "list-container-state",
                    format!("container state directory contains a non-UTF-8 entry: {name:?}"),
                )
            })?;
            let id = ContainerId::new(name.clone()).map_err(|error| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "list-container-state",
                    format!("container state directory contains invalid entry {name:?}: {error}"),
                )
            })?;
            let stored = self.load_stored_container(&id).await?;
            if request
                .isolation
                .is_none_or(|isolation| stored.record.isolation == isolation)
            {
                records.push(stored.record);
            }
        }
        records.sort_by(|left, right| left.state.id().cmp(right.state.id()));
        Ok(records)
    }
}

fn list_io_error(operation: &str, path: &std::path::Path, error: std::io::Error) -> Error {
    state_error(
        ErrorCode::Internal,
        "list-container-state",
        format!(
            "failed to {operation} durable container directory {}: {error}",
            path.display()
        ),
    )
}
