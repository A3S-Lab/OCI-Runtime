use std::collections::BTreeSet;
use std::path::PathBuf;

use a3s_oci_agent_protocol::{AgentTransportOperationStage, AgentTransportQualificationRequest};
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, ExecRequest, OperationId, SignalProcessRequest, StartRequest,
    WaitProcessRequest,
};

use super::QualificationHvfDriver;
use crate::{DriverExecRequest, DriverSignalProcessRequest, OciVmOperationReopenReplacementReport};

struct Qualification {
    shim: PathBuf,
    vm_rootfs: PathBuf,
    system_image_manifest: PathBuf,
    state_root: PathBuf,
    first_console: PathBuf,
    replacement_console: PathBuf,
    init_marker: PathBuf,
    exec_marker: PathBuf,
    init_marker_contents: Vec<u8>,
    exec_marker_contents: Vec<u8>,
    create: CreateRequest,
    start: StartRequest,
    exec: ExecRequest,
    signal_process: SignalProcessRequest,
    wait_process: WaitProcessRequest,
    delete_operation_id: OperationId,
    baseline_runtime_entries: BTreeSet<String>,
    stage: AgentTransportOperationStage,
    guest_qualification: Option<AgentTransportQualificationRequest>,
}

struct FirstOwnerEvidence {
    create_identity: (OperationId, ContainerTarget),
    start_identity: (OperationId, ContainerTarget),
    exec_record: a3s_oci_sdk::ProcessRecord,
    exec_identity: DriverExecRequest,
    signal_process_identity: DriverSignalProcessRequest,
    wait_process_identity: (a3s_oci_sdk::ProcessTarget, Option<u64>),
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
