//! Opt-in Native Linux Live Host reopen evidence gate.
//!
//! Proves `A3S_OCI_NATIVE_SESSION_SUPERVISOR=1` create+start → retained exec
//! I/O (Pipe stdin + Capture stdout) → FileOp::Upload → Host SIGKILL → init
//! survival → replacement Host reattaches Running with continuous init
//! identity, the same exec process ID (`retained_exec_io_proven`), and exact
//! FileOp::Download match (`retained_filesystem_proven`). Distinct from
//! stopped-only `native-linux-recovery`. Does not flip default create / B2 /
//! cutover flags.

mod host;
mod report;
mod runner;

pub use report::{
    LinuxNativeLiveRecoveryEvidence, LinuxNativeLiveRecoverySmokeReport,
    LINUX_NATIVE_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION,
};
pub use runner::run as linux_native_live_recovery_smoke;

use std::path::PathBuf;

/// Exact artifacts for one Native Live recovery smoke attempt.
#[derive(Debug, Clone)]
pub struct LinuxNativeLiveRecoverySmokeConfig {
    pub agent: PathBuf,
    pub bundle: PathBuf,
    pub work_parent: PathBuf,
    pub source_revision: Option<String>,
}
