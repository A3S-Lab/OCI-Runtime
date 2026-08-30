use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{CreateRequest, OperationId};

use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::OciVmOperationReopenReplacementReport;

mod first_owner;
mod replacement;
mod support;

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    create: &CreateRequest,
    start_operation_id: &OperationId,
    delete_operation_id: &OperationId,
    stage: AgentTransportOperationStage,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let first = first_owner::run(
        prepared,
        state_root,
        first_console,
        create,
        start_operation_id,
        stage,
        report,
    )
    .await?;
    replacement::run(
        prepared,
        state_root,
        replacement_console,
        create,
        delete_operation_id,
        first,
        report,
    )
    .await
}
