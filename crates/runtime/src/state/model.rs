use a3s_oci_sdk::{ContainerId, ContainerRecord, Generation, OperationId};
use serde::{Deserialize, Serialize};

pub(super) const ROOT_SCHEMA_VERSION: &str = "a3s.oci.runtime-root.v1";
pub(super) const CONTAINER_SCHEMA_VERSION: &str = "a3s.oci.container-record.v1";
pub(super) const GENERATION_SCHEMA_VERSION: &str = "a3s.oci.generation.v1";
pub(super) const OPERATION_SCHEMA_VERSION: &str = "a3s.oci.operation.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RuntimeRootMarker {
    pub schema_version: String,
}

impl Default for RuntimeRootMarker {
    fn default() -> Self {
        Self {
            schema_version: ROOT_SCHEMA_VERSION.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredGeneration {
    pub schema_version: String,
    pub id: ContainerId,
    pub last_generation: Generation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredContainer {
    pub schema_version: String,
    pub id: ContainerId,
    pub record: ContainerRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum StoredOperationKind {
    Create,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(super) enum StoredOperationStatus {
    Prepared,
    Succeeded { response: ContainerRecord },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredOperation {
    pub schema_version: String,
    pub operation_id: OperationId,
    pub kind: StoredOperationKind,
    pub container_id: ContainerId,
    pub generation: Generation,
    pub request_digest: String,
    pub outcome: StoredOperationStatus,
}
