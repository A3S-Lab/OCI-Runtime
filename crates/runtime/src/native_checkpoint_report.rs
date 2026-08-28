use std::collections::BTreeMap;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

/// Schema emitted by the real native Linux CRIU checkpoint qualification.
pub const NATIVE_LINUX_CHECKPOINT_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-checkpoint-smoke.v1";

/// Bounded evidence for immutable native Linux checkpoint creation and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeLinuxCheckpointSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub source_revision: String,
    pub checkpoint_advertised: bool,
    pub restore_not_advertised: bool,
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
    pub resume_succeeded: bool,
    pub artifact_survived_container_delete: bool,
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
            restore_not_advertised: false,
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
            resume_succeeded: false,
            artifact_survived_container_delete: false,
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

    /// Whether every immutable-artifact, retry, quiescence, and cleanup check passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.schema_version == NATIVE_LINUX_CHECKPOINT_SMOKE_SCHEMA_VERSION
            && self.platform == HostPlatform::Linux
            && self.status == CapabilityStatus::Available
            && !self.source_revision.is_empty()
            && self.checkpoint_advertised
            && self.restore_not_advertised
            && self.driver_evidence.contains_key("checkpoint_criu_digest")
            && self
                .driver_evidence
                .contains_key("checkpoint_driver_build_digest")
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
            && self.resume_succeeded
            && self.artifact_survived_container_delete
            && self.driver_journal_acknowledged
            && self.unpublished_partials_absent
            && self.executor_runtime_clean
            && self.session_root_clean
            && self.reason.is_none()
    }
}
