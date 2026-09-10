//! Opt-in Linux KVM Live Host reopen evidence gate.
//!
//! Proves `A3S_OCI_KVM_SESSION_OWNER=1` create+start → Host SIGKILL → Guest /
//! session-owner survive → replacement Host reattaches Running with continuous
//! init identity and no invented exit. Distinct from the stopped-only
//! `linux_kvm_recovery_smoke` schema.

mod report;
mod runner;

pub use report::{
    LinuxKvmLiveRecoveryEvidence, LinuxKvmLiveRecoverySmokeReport,
    LINUX_KVM_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION,
};
pub use runner::{run as linux_kvm_live_recovery_smoke, LinuxKvmLiveRecoverySmokeConfig};
