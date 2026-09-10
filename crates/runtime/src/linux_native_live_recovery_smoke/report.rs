use std::path::PathBuf;

use a3s_oci_core::CapabilityStatus;
use serde::{Deserialize, Serialize};

/// Schema for the Native Linux Live Host reopen evidence gate.
pub const LINUX_NATIVE_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.linux-native-live-recovery-smoke.v1";

/// Nested evidence for one Native Live Host reopen attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxNativeLiveRecoveryEvidence {
    pub session_supervisor_mode_opt_in: bool,
    pub file_upload_before_kill: bool,
    pub host_sigkill_delivered: bool,
    pub init_survived_host_sigkill: bool,
    pub replacement_state_running: bool,
    pub file_download_after_reattach: bool,
    pub retained_filesystem_proven: bool,
    pub retained_exec_io_proven: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LinuxNativeLiveRecoveryEvidence {
    fn initial() -> Self {
        Self {
            session_supervisor_mode_opt_in: false,
            file_upload_before_kill: false,
            host_sigkill_delivered: false,
            init_survived_host_sigkill: false,
            replacement_state_running: false,
            file_download_after_reattach: false,
            retained_filesystem_proven: false,
            retained_exec_io_proven: false,
            reason: None,
        }
    }

    /// Whether every Live filesystem continuity field is authentically set.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.session_supervisor_mode_opt_in
            && self.file_upload_before_kill
            && self.host_sigkill_delivered
            && self.init_survived_host_sigkill
            && self.replacement_state_running
            && self.file_download_after_reattach
            && self.retained_filesystem_proven
            && self.reason.is_none()
    }
}

/// Top-level Native Live recovery smoke report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxNativeLiveRecoverySmokeReport {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub case_count: u32,
    pub architecture: String,
    pub evidence_root: PathBuf,
    pub recovery: LinuxNativeLiveRecoveryEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LinuxNativeLiveRecoverySmokeReport {
    pub(super) fn initial(evidence_root: PathBuf, architecture: String) -> Self {
        Self {
            schema_version: LINUX_NATIVE_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            case_count: 0,
            architecture,
            evidence_root,
            recovery: LinuxNativeLiveRecoveryEvidence::initial(),
            reason: None,
        }
    }

    /// Whether the report records a complete Live success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.schema_version == LINUX_NATIVE_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION
            && self.status == CapabilityStatus::Available
            && self.case_count == 1
            && self.recovery.is_success()
            && self.reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_report_is_not_success_without_evidence() {
        let report = LinuxNativeLiveRecoverySmokeReport::initial(
            PathBuf::from("/tmp/native-live"),
            "x86_64".to_string(),
        );
        assert!(!report.is_success());
        assert!(!report.recovery.is_success());
    }
}
