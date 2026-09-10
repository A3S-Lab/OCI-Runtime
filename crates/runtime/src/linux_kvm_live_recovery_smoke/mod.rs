//! Opt-in Linux KVM Live Host reopen evidence gate.
//!
//! Proves `A3S_OCI_KVM_SESSION_OWNER=1` create+start → retained exec I/O
//! (Pipe stdin + Capture stdout) → Host SIGKILL → Guest / session-owner survive
//! → replacement Host reattaches Running with continuous init identity, the
//! same exec process ID, and post-reattach write_stdin/read_output — without
//! inventing an exit. Distinct from the stopped-only `linux_kvm_recovery_smoke`
//! schema. Does not claim Box `retained_stream_handle_proven` or flip B2 flags.

mod report;
mod runner;

pub use report::{
    LinuxKvmLiveRecoveryEvidence, LinuxKvmLiveRecoverySmokeReport,
    LINUX_KVM_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION,
};
pub use runner::{run as linux_kvm_live_recovery_smoke, LinuxKvmLiveRecoverySmokeConfig};
