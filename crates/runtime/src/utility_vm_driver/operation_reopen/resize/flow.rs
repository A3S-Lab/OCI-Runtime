use std::path::Path;

use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::OciVmOperationReopenReplacementReport;

use super::Qualification;

mod first_owner;
mod replacement;
pub(super) mod support;

pub(super) async fn exercise(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let first =
        first_owner::run(prepared, state_root, first_console, qualification, report).await?;
    replacement::run(
        prepared,
        state_root,
        replacement_console,
        qualification,
        first,
        report,
    )
    .await
}
