use std::path::PathBuf;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerTarget, ExitStatus, RuntimeOperation};
use serde::{Deserialize, Serialize};

pub const MACOS_HVF_HOST_SERVICE_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.macos-hvf-host-service-smoke.v1";

/// Exact macOS process incarnation retained for owner-death and leak checks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MacosProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub start_time_unix_us: u64,
    pub command: String,
}

/// Immutable inputs and executable digests used by one public-path run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHvfArtifactEvidence {
    pub host_service_executable: PathBuf,
    pub host_service_executable_sha256: String,
    pub shim: PathBuf,
    pub shim_sha256: String,
    pub system_image_manifest: PathBuf,
    pub system_image_manifest_sha256: String,
    pub source_bundle: PathBuf,
    pub source_bundle_config_digest: String,
    pub source_revision: String,
}

impl MacosHvfArtifactEvidence {
    fn is_complete(&self) -> bool {
        [
            &self.host_service_executable,
            &self.shim,
            &self.system_image_manifest,
            &self.source_bundle,
        ]
        .into_iter()
        .all(|path| path.is_absolute())
            && canonical_sha256(&self.host_service_executable_sha256)
            && canonical_sha256(&self.shim_sha256)
            && canonical_sha256(&self.system_image_manifest_sha256)
            && canonical_sha256_digest(&self.source_bundle_config_digest)
            && canonical_git_revision(&self.source_revision)
    }
}

/// All twenty driver operations plus feature, list, and event evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHvfPublicLifecycleEvidence {
    pub host_service_pid: Option<u32>,
    pub socket_private: bool,
    pub features_verified: bool,
    pub advertised_operations: Vec<RuntimeOperation>,
    pub exercised_operations: Vec<RuntimeOperation>,
    pub bundle_handoff_staged: bool,
    pub bundle_handoff_consumed: bool,
    pub create_returned_created: bool,
    pub create_replayed: bool,
    pub state_exact_after_create: bool,
    pub list_exact_after_create: bool,
    pub start_returned_running: bool,
    pub init_marker_verified: bool,
    pub process_io_verified: bool,
    pub terminal_io_verified: bool,
    pub exec_lifecycle_verified: bool,
    pub signal_process_verified: bool,
    pub wait_process_verified: bool,
    pub read_output_verified: bool,
    pub write_stdin_verified: bool,
    pub close_stdin_verified: bool,
    pub resize_verified: bool,
    pub file_transfer_verified: bool,
    pub filesystem_operations_verified: bool,
    pub process_inventory_verified: bool,
    pub resources_updated: bool,
    pub stats_verified: bool,
    pub pause_verified: bool,
    pub resume_verified: bool,
    pub wait_timeout_enforced: bool,
    pub kill_replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_status: Option<ExitStatus>,
    pub wait_replayed: bool,
    pub events_verified: bool,
    pub delete_replayed: bool,
    pub state_removed: bool,
    pub generation_monotonic: bool,
    pub stale_generation_rejected: bool,
    pub recreated_generation_deleted: bool,
    pub list_empty_after_delete: bool,
    pub service_descriptor_inventory_restored: bool,
    pub open_descriptors_before: Option<u32>,
    pub open_descriptors_after: Option<u32>,
    pub vm_processes_reaped: bool,
    pub endpoint_inventory_restored: bool,
    pub bundle_handoffs_clean: bool,
    pub runtime_shares_clean: bool,
    pub recovery_reports_clean: bool,
    pub console_files_created: u32,
    pub service_socket_removed: bool,
    pub service_exit_success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MacosHvfPublicLifecycleEvidence {
    pub fn is_success(&self) -> bool {
        self.host_service_pid.is_some()
            && self.socket_private
            && self.features_verified
            && self.advertised_operations.len() == 23
            && self.exercised_operations == self.advertised_operations
            && self.bundle_handoff_staged
            && self.bundle_handoff_consumed
            && self.create_returned_created
            && self.create_replayed
            && self.state_exact_after_create
            && self.list_exact_after_create
            && self.start_returned_running
            && self.init_marker_verified
            && self.process_io_verified
            && self.terminal_io_verified
            && self.exec_lifecycle_verified
            && self.signal_process_verified
            && self.wait_process_verified
            && self.read_output_verified
            && self.write_stdin_verified
            && self.close_stdin_verified
            && self.resize_verified
            && self.file_transfer_verified
            && self.filesystem_operations_verified
            && self.process_inventory_verified
            && self.resources_updated
            && self.stats_verified
            && self.pause_verified
            && self.resume_verified
            && self.wait_timeout_enforced
            && self.kill_replayed
            && self.wait_status == ExitStatus::signaled(libc::SIGKILL, false).ok()
            && self.wait_replayed
            && self.events_verified
            && self.delete_replayed
            && self.state_removed
            && self.generation_monotonic
            && self.stale_generation_rejected
            && self.recreated_generation_deleted
            && self.list_empty_after_delete
            && self.service_descriptor_inventory_restored
            && self.vm_processes_reaped
            && self.endpoint_inventory_restored
            && self.bundle_handoffs_clean
            && self.runtime_shares_clean
            && self.recovery_reports_clean
            && self.console_files_created >= 2
            && self.service_socket_removed
            && self.service_exit_success
            && self.reason.is_none()
    }
}

/// Evidence for SIGKILL owner death, authenticated recovery, and replacement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHvfOwnerDeathEvidence {
    pub first_host_service_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<ContainerTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_config_digest: Option<String>,
    pub live_vm_processes: Vec<MacosProcessIdentity>,
    pub host_service_sigkill_delivered: bool,
    pub first_host_service_reaped: bool,
    pub stale_socket_retained: bool,
    pub live_vm_processes_reaped: bool,
    pub endpoint_inventory_restored: bool,
    pub authenticated_recovery_report_retained: bool,
    pub replacement_host_service_pid: Option<u32>,
    pub replacement_socket_new_inode: bool,
    pub replacement_connected: bool,
    pub exact_stopped_state_recovered: bool,
    pub process_inventory_empty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_wait_status: Option<ExitStatus>,
    pub recovered_wait_replayed: bool,
    pub stopped_delete_succeeded: bool,
    pub durable_state_removed: bool,
    pub replacement_descriptor_inventory_restored: bool,
    pub open_descriptors_before: Option<u32>,
    pub open_descriptors_after: Option<u32>,
    pub bundle_handoffs_clean: bool,
    pub runtime_shares_clean: bool,
    pub recovery_reports_clean: bool,
    pub replacement_socket_removed: bool,
    pub replacement_exit_success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MacosHvfOwnerDeathEvidence {
    pub fn is_success(&self) -> bool {
        self.first_host_service_pid.is_some()
            && self.target.is_some()
            && self
                .created_config_digest
                .as_deref()
                .is_some_and(canonical_sha256_digest)
            && self.live_vm_processes.len() >= 2
            && self.host_service_sigkill_delivered
            && self.first_host_service_reaped
            && self.stale_socket_retained
            && self.live_vm_processes_reaped
            && self.endpoint_inventory_restored
            && self.authenticated_recovery_report_retained
            && self.replacement_host_service_pid.is_some()
            && self.replacement_socket_new_inode
            && self.replacement_connected
            && self.exact_stopped_state_recovered
            && self.process_inventory_empty
            && self.recovered_wait_status == ExitStatus::signaled(libc::SIGKILL, false).ok()
            && self.recovered_wait_replayed
            && self.stopped_delete_succeeded
            && self.durable_state_removed
            && self.replacement_descriptor_inventory_restored
            && self.bundle_handoffs_clean
            && self.runtime_shares_clean
            && self.recovery_reports_clean
            && self.replacement_socket_removed
            && self.replacement_exit_success
            && self.reason.is_none()
    }
}

/// Versioned 25-wave public Host Service soak evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHvfPublicSoakEvidence {
    pub requested_iterations: u32,
    pub completed_iterations: u32,
    pub host_service_pid: Option<u32>,
    pub completed_vm_generations: u32,
    pub create_replays_verified: u32,
    pub kill_replays_verified: u32,
    pub wait_replays_verified: u32,
    pub delete_replays_verified: u32,
    pub generation_monotonic_every_iteration: bool,
    pub stale_generation_rejected_every_iteration: bool,
    pub descriptor_inventory_stable_every_iteration: bool,
    pub steady_open_descriptors: Option<u32>,
    pub final_open_descriptors: Option<u32>,
    pub vm_processes_reaped_every_iteration: bool,
    pub endpoint_inventory_restored_every_iteration: bool,
    pub transients_clean_every_iteration: bool,
    pub unique_vm_processes: bool,
    pub vm_processes: Vec<MacosProcessIdentity>,
    pub console_files_created: u32,
    pub service_socket_removed: bool,
    pub service_exit_success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_iteration: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MacosHvfPublicSoakEvidence {
    pub fn initial(requested_iterations: u32) -> Self {
        Self {
            requested_iterations,
            generation_monotonic_every_iteration: true,
            stale_generation_rejected_every_iteration: true,
            descriptor_inventory_stable_every_iteration: true,
            vm_processes_reaped_every_iteration: true,
            endpoint_inventory_restored_every_iteration: true,
            transients_clean_every_iteration: true,
            unique_vm_processes: true,
            ..Self::default()
        }
    }

    pub fn is_success(&self) -> bool {
        self.requested_iterations >= 25
            && self.completed_iterations == self.requested_iterations
            && self.host_service_pid.is_some()
            && self.completed_vm_generations == self.requested_iterations
            && self.create_replays_verified == self.requested_iterations
            && self.kill_replays_verified == self.requested_iterations
            && self.wait_replays_verified == self.requested_iterations
            && self.delete_replays_verified == self.requested_iterations
            && self.generation_monotonic_every_iteration
            && self.stale_generation_rejected_every_iteration
            && self.descriptor_inventory_stable_every_iteration
            && self.vm_processes_reaped_every_iteration
            && self.endpoint_inventory_restored_every_iteration
            && self.transients_clean_every_iteration
            && self.unique_vm_processes
            && self.vm_processes.len() >= self.requested_iterations as usize * 2
            && self.console_files_created >= self.requested_iterations
            && self.service_socket_removed
            && self.service_exit_success
            && self.failure_iteration.is_none()
            && self.reason.is_none()
    }
}

/// Complete evidence for the public Apple Silicon Host Service product path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHvfHostServiceSmokeReport {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub evidence_root: PathBuf,
    pub artifacts: MacosHvfArtifactEvidence,
    pub lifecycle: MacosHvfPublicLifecycleEvidence,
    pub owner_death: MacosHvfOwnerDeathEvidence,
    pub soak: MacosHvfPublicSoakEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MacosHvfHostServiceSmokeReport {
    pub fn initial(evidence_root: PathBuf, requested_iterations: u32) -> Self {
        Self {
            schema_version: MACOS_HVF_HOST_SERVICE_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            platform: HostPlatform::Macos,
            evidence_root,
            artifacts: MacosHvfArtifactEvidence::default(),
            lifecycle: MacosHvfPublicLifecycleEvidence::default(),
            owner_death: MacosHvfOwnerDeathEvidence::default(),
            soak: MacosHvfPublicSoakEvidence::initial(requested_iterations),
            reason: None,
        }
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        self.schema_version == MACOS_HVF_HOST_SERVICE_SMOKE_SCHEMA_VERSION
            && self.status == CapabilityStatus::Available
            && self.platform == HostPlatform::Macos
            && self.evidence_root.is_absolute()
            && self.artifacts.is_complete()
            && self.lifecycle.is_success()
            && self.owner_death.is_success()
            && self.soak.is_success()
            && self.reason.is_none()
    }
}

pub(super) fn canonical_git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(canonical_sha256)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{canonical_git_revision, MacosHvfArtifactEvidence, MacosHvfHostServiceSmokeReport};

    fn complete_artifacts() -> MacosHvfArtifactEvidence {
        MacosHvfArtifactEvidence {
            host_service_executable: PathBuf::from("/tmp/a3s-oci"),
            host_service_executable_sha256: "1".repeat(64),
            shim: PathBuf::from("/tmp/a3s-oci-krun-shim"),
            shim_sha256: "2".repeat(64),
            system_image_manifest: PathBuf::from("/tmp/system-image.json"),
            system_image_manifest_sha256: "3".repeat(64),
            source_bundle: PathBuf::from("/tmp/bundle"),
            source_bundle_config_digest: format!("sha256:{}", "4".repeat(64)),
            source_revision: "5".repeat(40),
        }
    }

    #[test]
    fn artifact_evidence_requires_canonical_digests_and_full_git_revision() {
        let complete = complete_artifacts();
        assert!(complete.is_complete());
        assert!(canonical_git_revision(&"a".repeat(40)));

        for invalid in ["a".repeat(39), "A".repeat(40), "g".repeat(40)] {
            let mut evidence = complete.clone();
            evidence.source_revision = invalid;
            assert!(!evidence.is_complete());
        }

        let mut evidence = complete.clone();
        evidence.shim_sha256 = "f".repeat(63);
        assert!(!evidence.is_complete());

        let mut evidence = complete.clone();
        evidence.source_bundle_config_digest = "4".repeat(64);
        assert!(!evidence.is_complete());

        let mut evidence = complete;
        evidence.source_bundle = PathBuf::from("relative/bundle");
        assert!(!evidence.is_complete());
    }

    #[test]
    fn report_envelope_fails_closed_without_complete_provenance() {
        let mut report =
            MacosHvfHostServiceSmokeReport::initial(PathBuf::from("/tmp/evidence"), 25);
        report.artifacts = complete_artifacts();
        assert!(
            !report.is_success(),
            "phase evidence is intentionally absent"
        );

        report.artifacts.source_revision.clear();
        assert!(!report.artifacts.is_complete());
        report.schema_version = "a3s.oci.macos-hvf-host-service-smoke.unknown".into();
        assert!(!report.is_success());
    }
}
