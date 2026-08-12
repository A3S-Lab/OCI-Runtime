use std::collections::BTreeSet;
use std::path::PathBuf;

use a3s_oci_agent_protocol::{AgentTransportOperationStage, AgentTransportQualificationRequest};
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, FileRequest, FilesystemRequest, OperationId, StartRequest,
};

use super::QualificationHvfDriver;
use crate::OciVmOperationReopenReplacementReport;

struct Qualification {
    shim: PathBuf,
    vm_rootfs: PathBuf,
    system_image_manifest: PathBuf,
    state_root: PathBuf,
    first_console: PathBuf,
    replacement_console: PathBuf,
    init_marker: PathBuf,
    init_marker_contents: Vec<u8>,
    create: CreateRequest,
    start: StartRequest,
    file: FileRequest,
    download: FileRequest,
    cleanup_file: FilesystemRequest,
    delete_operation_id: OperationId,
    stale_guest_operation_id: OperationId,
    stale_host_operation_id: OperationId,
    baseline_runtime_entries: BTreeSet<String>,
    stage: AgentTransportOperationStage,
    guest_qualification: Option<AgentTransportQualificationRequest>,
    expected_payload: Vec<u8>,
}

struct FirstOwnerEvidence {
    create_identity: (OperationId, ContainerTarget),
    start_identity: (OperationId, ContainerTarget),
    file_identity: FileRequest,
}

mod entry;
pub(in crate::oci_smoke::utility_vm) use entry::run;
mod first_owner;
mod replacement;
pub(in crate::oci_smoke::utility_vm::reopen_replacement) mod support;

async fn exercise(
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<(), String> {
    let first = first_owner::run(qualification, report).await?;
    replacement::run(qualification, &first, report).await
}
