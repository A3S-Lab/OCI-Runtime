use a3s_oci_sdk::{
    ContainerId, ContainerRecord, Error, ExitStatus, Generation, OperationId, ProcessId,
    ProcessRecord, RuntimeEvent,
};
use serde::{Deserialize, Serialize};

pub(super) const ROOT_SCHEMA_VERSION: &str = "a3s.oci.runtime-root.v1";
pub(super) const CONTAINER_SCHEMA_VERSION: &str = "a3s.oci.container-record.v1";
pub(super) const GENERATION_SCHEMA_VERSION: &str = "a3s.oci.generation.v1";
pub(super) const OPERATION_SCHEMA_VERSION: &str = "a3s.oci.operation.v1";
pub(super) const PROCESS_SCHEMA_VERSION: &str = "a3s.oci.process-record.v1";
pub(super) const EVENT_CURSOR_SCHEMA_VERSION: &str = "a3s.oci.event-cursor.v1";
pub(super) const EVENT_CLAIM_SCHEMA_VERSION: &str = "a3s.oci.event-claim.v1";
pub(super) const EVENT_RECORD_SCHEMA_VERSION: &str = "a3s.oci.event-record.v1";

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_operation: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_exit_status: Option<ExitStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredProcess {
    pub schema_version: String,
    pub record: ProcessRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_operation: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<ExitStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredEventCursor {
    pub schema_version: String,
    pub last_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredEventClaim {
    pub schema_version: String,
    pub identity: String,
    pub event: RuntimeEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredEventRecord {
    pub schema_version: String,
    pub event: RuntimeEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum StoredOperationKind {
    Create,
    Start,
    Kill,
    Delete,
    Exec,
    SignalProcess,
    WriteStdin,
    CloseStdin,
    Resize,
    Pause,
    Resume,
    Update,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(super) enum StoredOperationStatus {
    Prepared,
    Succeeded { response: ContainerRecord },
    SucceededProcess { response: ProcessRecord },
    SucceededEmpty,
    Failed { error: Error },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredOperation {
    pub schema_version: String,
    pub operation_id: OperationId,
    pub kind: StoredOperationKind,
    pub container_id: ContainerId,
    pub generation: Generation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<ProcessId>,
    pub request_digest: String,
    pub outcome: StoredOperationStatus,
}
