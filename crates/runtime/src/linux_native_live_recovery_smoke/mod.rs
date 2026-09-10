//! Opt-in Native Linux Live Host reopen evidence gate (stub).
//!
//! Product path: Host-reopen `LinuxLiveSupervisedSession::{file,filesystem}`
//! plus `NativeLinuxDriver` `live_for` routing. First-principles unit coverage
//! lives in `a3s-oci-agent` recovery tests.
//!
//! TODO(evidence): implement the full Host SIGKILL → Running reattach smoke
//! (schema fields below) under `A3S_OCI_NATIVE_SESSION_SUPERVISOR=1`, distinct
//! from stopped-only `native-linux-recovery`. Until then this module returns
//! Unavailable without inventing greened evidence.

mod report;

pub use report::{
    LinuxNativeLiveRecoveryEvidence, LinuxNativeLiveRecoverySmokeReport,
    LINUX_NATIVE_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION,
};

use std::path::PathBuf;

use a3s_oci_core::CapabilityStatus;

/// Exact artifacts for one Native Live recovery smoke attempt.
#[derive(Debug, Clone)]
pub struct LinuxNativeLiveRecoverySmokeConfig {
    pub agent: PathBuf,
    pub bundle: PathBuf,
    pub work_parent: PathBuf,
    pub source_revision: Option<String>,
}

/// Fail-closed stub until the supervised Live Host reopen evidence harness lands.
pub async fn linux_native_live_recovery_smoke(
    config: LinuxNativeLiveRecoverySmokeConfig,
) -> LinuxNativeLiveRecoverySmokeReport {
    let mut report = LinuxNativeLiveRecoverySmokeReport::initial(
        config.work_parent.clone(),
        std::env::consts::ARCH.to_string(),
    );
    report.recovery.session_supervisor_mode_opt_in = std::env::var_os(
        "A3S_OCI_NATIVE_SESSION_SUPERVISOR",
    )
    .is_some_and(|value| value == "1");
    report.status = CapabilityStatus::Unavailable;
    report.case_count = 0;
    report.reason = Some(
        "native Live Host reopen filesystem evidence harness is not implemented yet; \
         product path and unit tests land first (see ROADMAP TODO for \
         a3s.oci.linux-native-live-recovery-smoke.v1)"
            .to_string(),
    );
    report.recovery.reason = report.reason.clone();
    let _ = (config.agent, config.bundle, config.source_revision);
    report
}
