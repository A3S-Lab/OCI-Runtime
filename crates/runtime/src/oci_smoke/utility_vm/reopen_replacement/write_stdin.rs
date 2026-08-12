use std::collections::BTreeSet;
use std::path::PathBuf;

use a3s_oci_agent_protocol::{AgentTransportOperationStage, AgentTransportQualificationRequest};
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, ExecRequest, OperationId, StartRequest, WriteStdinRequest,
};

use super::QualificationHvfDriver;
use crate::{DriverExecRequest, DriverWriteStdinRequest, OciVmOperationReopenReplacementReport};

pub(super) const WRITE_MARKER_NAME: &str = ".a3s-oci-write-stdin-reopen-smoke";

struct Qualification {
    shim: PathBuf,
    vm_rootfs: PathBuf,
    system_image_manifest: PathBuf,
    state_root: PathBuf,
    first_console: PathBuf,
    replacement_console: PathBuf,
    init_marker: PathBuf,
    exec_marker: PathBuf,
    write_marker: PathBuf,
    init_marker_contents: Vec<u8>,
    exec_marker_contents: Vec<u8>,
    write_marker_contents: Vec<u8>,
    create: CreateRequest,
    start: StartRequest,
    exec: ExecRequest,
    write_stdin: WriteStdinRequest,
    delete_operation_id: OperationId,
    stale_guest_operation_id: OperationId,
    stale_host_operation_id: OperationId,
    baseline_runtime_entries: BTreeSet<String>,
    stage: AgentTransportOperationStage,
    guest_qualification: Option<AgentTransportQualificationRequest>,
}

struct FirstOwnerEvidence {
    create_identity: (OperationId, ContainerTarget),
    start_identity: (OperationId, ContainerTarget),
    exec_identity: DriverExecRequest,
    write_stdin_identity: DriverWriteStdinRequest,
}

mod entry;
pub(in crate::oci_smoke::utility_vm) use entry::run;
mod first_owner;
mod replacement;
mod support;

async fn exercise(
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<(), String> {
    let first = first_owner::run(qualification, report).await?;
    replacement::run(qualification, &first, report).await
}
