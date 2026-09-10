use std::path::PathBuf;

use a3s_oci_core::CapabilityStatus;
use serde::{Deserialize, Serialize};

/// Schema for the Native Linux Live Host reopen evidence gate.
pub const LINUX_NATIVE_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.linux-native-live-recovery-smoke.v1";

/// Nested evidence for one Native Live Host reopen attempt.
///
/// JSON field names stay snake_case (same as KVM Live recovery) so the
/// qualification wrapper jq can read `schema_version` /
/// `session_supervisor_mode_opt_in` without camelCase aliases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    ///
    /// `retained_exec_io_proven` is optional for v1 (filesystem-only success).
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

    fn complete_filesystem_evidence() -> LinuxNativeLiveRecoveryEvidence {
        LinuxNativeLiveRecoveryEvidence {
            session_supervisor_mode_opt_in: true,
            file_upload_before_kill: true,
            host_sigkill_delivered: true,
            init_survived_host_sigkill: true,
            replacement_state_running: true,
            file_download_after_reattach: true,
            retained_filesystem_proven: true,
            retained_exec_io_proven: false,
            reason: None,
        }
    }

    #[test]
    fn stub_report_is_not_success_without_evidence() {
        let report = LinuxNativeLiveRecoverySmokeReport::initial(
            PathBuf::from("/tmp/native-live"),
            "x86_64".to_string(),
        );
        assert!(!report.is_success());
        assert!(!report.recovery.is_success());
    }

    #[test]
    fn success_requires_filesystem_continuity_fields() {
        let evidence = complete_filesystem_evidence();
        assert!(evidence.is_success());

        let mut missing_upload = evidence.clone();
        missing_upload.file_upload_before_kill = false;
        assert!(!missing_upload.is_success());

        let mut missing_download = evidence.clone();
        missing_download.file_download_after_reattach = false;
        assert!(!missing_download.is_success());

        let mut missing_proven = evidence.clone();
        missing_proven.retained_filesystem_proven = false;
        assert!(!missing_proven.is_success());

        let mut missing_running = evidence.clone();
        missing_running.replacement_state_running = false;
        assert!(!missing_running.is_success());

        let mut missing_survival = evidence.clone();
        missing_survival.init_survived_host_sigkill = false;
        assert!(!missing_survival.is_success());
    }

    #[test]
    fn report_success_requires_available_case_and_filesystem_evidence() {
        let mut report = LinuxNativeLiveRecoverySmokeReport::initial(
            PathBuf::from("/tmp/native-live"),
            "x86_64".to_string(),
        );
        report.status = CapabilityStatus::Available;
        report.case_count = 1;
        report.recovery = complete_filesystem_evidence();
        assert!(report.is_success());

        report.recovery.retained_filesystem_proven = false;
        assert!(!report.is_success());
    }

    #[test]
    fn retained_exec_io_is_not_required_for_v1_success() {
        let mut evidence = complete_filesystem_evidence();
        evidence.retained_exec_io_proven = false;
        assert!(evidence.is_success());
        evidence.retained_exec_io_proven = true;
        assert!(evidence.is_success());
    }

    #[test]
    fn report_json_uses_snake_case_keys() {
        let mut report = LinuxNativeLiveRecoverySmokeReport::initial(
            PathBuf::from("/tmp/native-live"),
            "x86_64".to_string(),
        );
        report.status = CapabilityStatus::Available;
        report.case_count = 1;
        report.recovery = complete_filesystem_evidence();
        let json = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(
            json.get("schema_version").and_then(|value| value.as_str()),
            Some(LINUX_NATIVE_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION)
        );
        assert!(json.get("schemaVersion").is_none());
        let recovery = json.get("recovery").expect("recovery object");
        assert_eq!(
            recovery
                .get("session_supervisor_mode_opt_in")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert!(recovery.get("sessionSupervisorModeOptIn").is_none());
        assert_eq!(
            recovery
                .get("retained_filesystem_proven")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert!(recovery.get("retainedFilesystemProven").is_none());
    }
}
