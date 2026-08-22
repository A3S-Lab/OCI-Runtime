use std::sync::LazyLock;

use a3s_oci_sdk::{OciLinuxSupport, Result};

static SHARED_EXECUTOR_SUPPORT: LazyLock<Result<OciLinuxSupport>> =
    LazyLock::new(OciLinuxSupport::shared_executor);

pub(super) fn shared() -> Result<&'static OciLinuxSupport> {
    SHARED_EXECUTOR_SUPPORT.as_ref().map_err(Clone::clone)
}
