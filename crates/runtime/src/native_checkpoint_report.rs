use std::collections::BTreeMap;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

/// Schema emitted by the real native Linux CRIU checkpoint qualification.
pub const NATIVE_LINUX_CHECKPOINT_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-checkpoint-smoke.v3";

/// Exact restore boundary at which a qualification owner terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeLinuxCheckpointRestoreCrashPoint {
    AfterDriverCall,
    AfterHostCommit,
}

/// Bounded evidence for immutable native Linux checkpoint and restore replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeLinuxCheckpointSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub source_revision: String,
    pub checkpoint_advertised: bool,
    pub restore_advertised: bool,
    pub driver_evidence: BTreeMap<String, String>,
    pub lifecycle_started: bool,
    pub paused_source_observed: bool,
    pub preexisting_destination_rejected: bool,
    pub preexisting_destination_preserved: bool,
    pub driver_after_call_fault_injected: bool,
    pub artifact_published_before_host_commit: bool,
    pub driver_replay_completed_host_commit: bool,
    pub host_replay_exact: bool,
    pub artifact_digest_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_size_bytes: Option<u64>,
    pub artifact_bytes_unchanged_across_replay: bool,
    pub source_remained_paused: bool,
    pub source_resume_succeeded: bool,
    pub artifact_survived_source_delete: bool,
    pub restore_after_call_fault_injected: bool,
    pub driver_restore_replay_completed_host_commit: bool,
    pub restore_host_replay_exact: bool,
    pub restored_generation_newer: bool,
    pub restored_running_paused: bool,
    pub restored_state_exact: bool,
    pub restored_resume_succeeded: bool,
    pub restored_exit_status_exact: bool,
    pub artifact_bytes_unchanged_across_restore: bool,
    pub artifact_survived_restored_delete: bool,
    pub restore_after_call_owner_replaced: bool,
    pub restore_after_call_service_reopened: bool,
    pub restore_after_call_replay_exact: bool,
    pub restore_after_commit_owner_replaced: bool,
    pub restore_after_commit_service_reopened: bool,
    pub restore_after_commit_replay_exact: bool,
    pub cross_process_restored_pids_live: bool,
    pub cross_process_artifact_unchanged: bool,
    pub cross_process_restore_cleanup_exact: bool,
    pub driver_journal_acknowledged: bool,
    pub unpublished_partials_absent: bool,
    pub executor_runtime_clean: bool,
    pub session_root_clean: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxCheckpointSmokeReport {
    pub(crate) fn initial(platform: HostPlatform, source_revision: String) -> Self {
        Self {
            schema_version: NATIVE_LINUX_CHECKPOINT_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            source_revision,
            checkpoint_advertised: false,
            restore_advertised: false,
            driver_evidence: BTreeMap::new(),
            lifecycle_started: false,
            paused_source_observed: false,
            preexisting_destination_rejected: false,
            preexisting_destination_preserved: false,
            driver_after_call_fault_injected: false,
            artifact_published_before_host_commit: false,
            driver_replay_completed_host_commit: false,
            host_replay_exact: false,
            artifact_digest_verified: false,
            artifact_digest: None,
            artifact_size_bytes: None,
            artifact_bytes_unchanged_across_replay: false,
            source_remained_paused: false,
            source_resume_succeeded: false,
            artifact_survived_source_delete: false,
            restore_after_call_fault_injected: false,
            driver_restore_replay_completed_host_commit: false,
            restore_host_replay_exact: false,
            restored_generation_newer: false,
            restored_running_paused: false,
            restored_state_exact: false,
            restored_resume_succeeded: false,
            restored_exit_status_exact: false,
            artifact_bytes_unchanged_across_restore: false,
            artifact_survived_restored_delete: false,
            restore_after_call_owner_replaced: false,
            restore_after_call_service_reopened: false,
            restore_after_call_replay_exact: false,
            restore_after_commit_owner_replaced: false,
            restore_after_commit_service_reopened: false,
            restore_after_commit_replay_exact: false,
            cross_process_restored_pids_live: false,
            cross_process_artifact_unchanged: false,
            cross_process_restore_cleanup_exact: false,
            driver_journal_acknowledged: false,
            unpublished_partials_absent: false,
            executor_runtime_clean: false,
            session_root_clean: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(platform: HostPlatform, source_revision: String) -> Self {
        let mut report = Self::initial(platform, source_revision);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("native CRIU checkpoint qualification requires Linux".to_string());
        report
    }

    pub(crate) fn driver_source_revision_matches(&self) -> bool {
        self.driver_evidence
            .get("checkpoint_source_revision")
            .is_some_and(|revision| revision == &self.source_revision)
    }

    /// Whether every immutable-artifact, retry, quiescence, and cleanup check passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.schema_version == NATIVE_LINUX_CHECKPOINT_SMOKE_SCHEMA_VERSION
            && self.platform == HostPlatform::Linux
            && self.status == CapabilityStatus::Available
            && !self.source_revision.is_empty()
            && self.checkpoint_advertised
            && self.restore_advertised
            && self.driver_evidence.contains_key("checkpoint_criu_digest")
            && self
                .driver_evidence
                .contains_key("checkpoint_driver_build_digest")
            && self.driver_source_revision_matches()
            && self.lifecycle_started
            && self.paused_source_observed
            && self.preexisting_destination_rejected
            && self.preexisting_destination_preserved
            && self.driver_after_call_fault_injected
            && self.artifact_published_before_host_commit
            && self.driver_replay_completed_host_commit
            && self.host_replay_exact
            && self.artifact_digest_verified
            && self.artifact_digest.is_some()
            && self.artifact_size_bytes.is_some_and(|size| size > 0)
            && self.artifact_bytes_unchanged_across_replay
            && self.source_remained_paused
            && self.source_resume_succeeded
            && self.artifact_survived_source_delete
            && self.restore_after_call_fault_injected
            && self.driver_restore_replay_completed_host_commit
            && self.restore_host_replay_exact
            && self.restored_generation_newer
            && self.restored_running_paused
            && self.restored_state_exact
            && self.restored_resume_succeeded
            && self.restored_exit_status_exact
            && self.artifact_bytes_unchanged_across_restore
            && self.artifact_survived_restored_delete
            && self.restore_after_call_owner_replaced
            && self.restore_after_call_service_reopened
            && self.restore_after_call_replay_exact
            && self.restore_after_commit_owner_replaced
            && self.restore_after_commit_service_reopened
            && self.restore_after_commit_replay_exact
            && self.cross_process_restored_pids_live
            && self.cross_process_artifact_unchanged
            && self.cross_process_restore_cleanup_exact
            && self.driver_journal_acknowledged
            && self.unpublished_partials_absent
            && self.executor_runtime_clean
            && self.session_root_clean
            && self.reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::HostPlatform;

    use super::NativeLinuxCheckpointSmokeReport;

    #[test]
    fn driver_source_revision_must_match_the_report_source() {
        let source_revision = "a".repeat(40);
        let mut report =
            NativeLinuxCheckpointSmokeReport::initial(HostPlatform::Linux, source_revision.clone());

        assert!(!report.driver_source_revision_matches());
        report
            .driver_evidence
            .insert("checkpoint_source_revision".to_string(), "b".repeat(40));
        assert!(!report.driver_source_revision_matches());
        report
            .driver_evidence
            .insert("checkpoint_source_revision".to_string(), source_revision);
        assert!(report.driver_source_revision_matches());
    }
}
