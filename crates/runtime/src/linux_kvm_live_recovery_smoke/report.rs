use std::path::PathBuf;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::ContainerTarget;
use serde::{Deserialize, Serialize};

use crate::linux_kvm_recovery_smoke::report::canonical_sha256_digest;
use crate::linux_kvm_recovery_smoke::{LinuxKvmRecoveryArtifacts, LinuxProcessIdentity};

pub const LINUX_KVM_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.linux-kvm-live-recovery-smoke.v3";

/// Live Host reopen evidence: Guest survives Host SIGKILL and reattaches Running.
///
/// v3 keeps v2 retained exec I/O, proves filesystem continuity
/// (FileOp::Upload before Host SIGKILL, FileOp::Download after reattach on the
/// same Running generation), and proves a **new** post-reattach Pipe+Capture
/// exec (`new_exec_io_after_reattach_proven`) — matching Native Live v3 spawn
/// coverage through the reattached Guest agent. Does **not** flip Box harness
/// `b2_process_session_recovery_closed` (reports never self-certify B2/R6
/// close).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKvmLiveRecoveryEvidence {
    pub session_owner_mode_durable: bool,
    pub qualification_scope_verified: bool,
    pub first_host_service: Option<LinuxProcessIdentity>,
    pub first_socket_peer: Option<LinuxProcessIdentity>,
    pub target: Option<ContainerTarget>,
    pub created_config_digest: Option<String>,
    pub create_replayed: bool,
    pub start_returned_running: bool,
    pub init_marker_verified: bool,
    pub init_pid_before: Option<u32>,
    pub live_vm_processes: Vec<LinuxProcessIdentity>,
    pub session_owner_identity: Option<LinuxProcessIdentity>,
    pub shim_identity: Option<LinuxProcessIdentity>,
    pub live_binding_published: bool,
    /// Durable Live keeps `/tmp/<pipe>/` (agent + host-control) for reattach.
    pub durable_guest_endpoint_retained: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durable_pipe_name: Option<String>,
    /// Exec process ID retained across Host SIGKILL for I/O continuity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retained_exec_process_id: Option<String>,
    /// First Host proved write_stdin + read_output echo before SIGKILL.
    pub exec_io_before_kill: bool,
    /// Replacement Host write_stdin on the same process ID succeeded.
    pub write_stdin_after_reattach: bool,
    /// Replacement Host read_output observed the post-reattach echo.
    pub read_output_after_reattach: bool,
    /// Aggregate: before-kill I/O + after-reattach write + read on same exec.
    pub retained_exec_io_proven: bool,
    /// New exec process ID spawned by the replacement Host after reattach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_exec_process_id: Option<String>,
    /// Replacement Host proved Pipe+Capture I/O on a newly spawned exec.
    pub new_exec_io_after_reattach_proven: bool,
    /// First Host uploaded a unique payload under a known container path.
    pub file_upload_before_kill: bool,
    /// Replacement Host downloaded the same path after Running reattach.
    pub file_download_after_reattach: bool,
    /// Aggregate: upload before kill + exact download match after reattach.
    pub retained_filesystem_proven: bool,
    pub host_service_sigkill_delivered: bool,
    pub first_host_service_reaped: bool,
    pub stale_socket_retained: bool,
    /// Must remain false for Live success (opposite of stopped-only recovery).
    pub live_vm_processes_reaped: bool,
    pub guest_survived_host_sigkill: bool,
    pub live_binding_authenticated_after_kill: bool,
    pub replacement_host_service: Option<LinuxProcessIdentity>,
    pub replacement_socket_peer: Option<LinuxProcessIdentity>,
    pub replacement_socket_new_owner: bool,
    pub replacement_connected: bool,
    pub replacement_state_running: bool,
    pub init_pid_after: Option<u32>,
    pub init_identity_unchanged: bool,
    pub no_invented_exit_status: bool,
    pub process_inventory_nonempty: bool,
    pub force_cleanup_succeeded: bool,
    pub replacement_exit_success: bool,
    pub replacement_socket_removed: bool,
    pub durable_guest_endpoint_cleaned: bool,
    pub service_restart_recovered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LinuxKvmLiveRecoveryEvidence {
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.session_owner_mode_durable
            && self.qualification_scope_verified
            && self.first_host_service.is_some()
            && self.first_socket_peer == self.first_host_service
            && self.target.is_some()
            && self
                .created_config_digest
                .as_deref()
                .is_some_and(canonical_sha256_digest)
            && self.create_replayed
            && self.start_returned_running
            && self.init_marker_verified
            && self.init_pid_before.is_some_and(|pid| pid > 0)
            && self.live_vm_processes.len() >= 2
            && self.session_owner_identity.is_some()
            && self.shim_identity.is_some()
            && self.live_binding_published
            && self.durable_guest_endpoint_retained
            && self
                .durable_pipe_name
                .as_deref()
                .is_some_and(|name| name.starts_with("a3s-oci-agent-") && name.len() > 16)
            && self
                .retained_exec_process_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
            && self.exec_io_before_kill
            && self.write_stdin_after_reattach
            && self.read_output_after_reattach
            && self.retained_exec_io_proven
            && self
                .new_exec_process_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
            && self.new_exec_io_after_reattach_proven
            && self.file_upload_before_kill
            && self.file_download_after_reattach
            && self.retained_filesystem_proven
            && self.host_service_sigkill_delivered
            && self.first_host_service_reaped
            && self.stale_socket_retained
            && !self.live_vm_processes_reaped
            && self.guest_survived_host_sigkill
            && self.live_binding_authenticated_after_kill
            && self.replacement_host_service.is_some()
            && self.replacement_socket_peer == self.replacement_host_service
            && self.first_socket_peer != self.replacement_socket_peer
            && self.replacement_socket_new_owner
            && self.replacement_connected
            && self.replacement_state_running
            && self.init_pid_after == self.init_pid_before
            && self.init_identity_unchanged
            && self.no_invented_exit_status
            && self.process_inventory_nonempty
            && self.force_cleanup_succeeded
            && self.replacement_exit_success
            && self.replacement_socket_removed
            && self.durable_guest_endpoint_cleaned
            && self.service_restart_recovered
            && self.reason.is_none()
    }
}

/// Complete Linux KVM Live Host reopen report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKvmLiveRecoverySmokeReport {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub architecture: String,
    pub kvm_required: bool,
    pub expected_case_count: u32,
    pub case_count: u32,
    pub evidence_root: PathBuf,
    pub artifacts: LinuxKvmRecoveryArtifacts,
    pub recovery: LinuxKvmLiveRecoveryEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LinuxKvmLiveRecoverySmokeReport {
    pub(super) fn initial(evidence_root: PathBuf, architecture: String) -> Self {
        Self {
            schema_version: LINUX_KVM_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            platform: HostPlatform::Linux,
            architecture,
            kvm_required: true,
            expected_case_count: 1,
            case_count: 0,
            evidence_root,
            artifacts: LinuxKvmRecoveryArtifacts::default(),
            recovery: LinuxKvmLiveRecoveryEvidence::default(),
            reason: None,
        }
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        self.schema_version == LINUX_KVM_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION
            && self.status == CapabilityStatus::Available
            && self.platform == HostPlatform::Linux
            && matches!(self.architecture.as_str(), "x86_64" | "aarch64")
            && self.kvm_required
            && self.expected_case_count == 1
            && self.case_count == 1
            && self.evidence_root.is_absolute()
            && self.artifacts.is_complete()
            && self.recovery.is_success()
            && self.reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ContainerId, Generation};

    use super::*;

    fn process(pid: u32, parent_pid: u32) -> LinuxProcessIdentity {
        LinuxProcessIdentity {
            pid,
            parent_pid,
            process_group_id: pid,
            start_time_ticks: u64::from(pid) * 10,
            command: "a3s-oci-krun-shim".to_string(),
        }
    }

    fn complete_report() -> LinuxKvmLiveRecoverySmokeReport {
        let first = process(101, 100);
        let replacement = process(201, 100);
        let owner = process(102, 101);
        let shim = process(103, 102);
        LinuxKvmLiveRecoverySmokeReport {
            schema_version: LINUX_KVM_LIVE_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Available,
            platform: HostPlatform::Linux,
            architecture: "x86_64".to_string(),
            kvm_required: true,
            expected_case_count: 1,
            case_count: 1,
            evidence_root: PathBuf::from("/tmp/evidence"),
            artifacts: LinuxKvmRecoveryArtifacts {
                host_service_executable: PathBuf::from("/tmp/a3s-oci"),
                host_service_executable_sha256: "1".repeat(64),
                shim: PathBuf::from("/tmp/a3s-oci-krun-shim"),
                shim_sha256: "2".repeat(64),
                system_image_manifest: PathBuf::from("/tmp/system-image.json"),
                system_image_manifest_sha256: "3".repeat(64),
                source_bundle: PathBuf::from("/tmp/bundle"),
                source_bundle_config_digest: format!("sha256:{}", "4".repeat(64)),
                source_revision: "5".repeat(40),
            },
            recovery: LinuxKvmLiveRecoveryEvidence {
                session_owner_mode_durable: true,
                qualification_scope_verified: true,
                first_host_service: Some(first.clone()),
                first_socket_peer: Some(first),
                target: Some(ContainerTarget::exact(
                    ContainerId::new("kvm-live-recovery").expect("container ID"),
                    Generation(1),
                )),
                created_config_digest: Some(format!("sha256:{}", "6".repeat(64))),
                create_replayed: true,
                start_returned_running: true,
                init_marker_verified: true,
                init_pid_before: Some(1),
                live_vm_processes: vec![owner.clone(), shim.clone()],
                session_owner_identity: Some(owner),
                shim_identity: Some(shim),
                live_binding_published: true,
                durable_guest_endpoint_retained: true,
                durable_pipe_name: Some(format!("a3s-oci-agent-{}", "a".repeat(32))),
                retained_exec_process_id: Some("live-io-exec".to_string()),
                exec_io_before_kill: true,
                write_stdin_after_reattach: true,
                read_output_after_reattach: true,
                retained_exec_io_proven: true,
                new_exec_process_id: Some("live-new-exec".to_string()),
                new_exec_io_after_reattach_proven: true,
                file_upload_before_kill: true,
                file_download_after_reattach: true,
                retained_filesystem_proven: true,
                host_service_sigkill_delivered: true,
                first_host_service_reaped: true,
                stale_socket_retained: true,
                live_vm_processes_reaped: false,
                guest_survived_host_sigkill: true,
                live_binding_authenticated_after_kill: true,
                replacement_host_service: Some(replacement.clone()),
                replacement_socket_peer: Some(replacement),
                replacement_socket_new_owner: true,
                replacement_connected: true,
                replacement_state_running: true,
                init_pid_after: Some(1),
                init_identity_unchanged: true,
                no_invented_exit_status: true,
                process_inventory_nonempty: true,
                force_cleanup_succeeded: true,
                replacement_exit_success: true,
                replacement_socket_removed: true,
                durable_guest_endpoint_cleaned: true,
                service_restart_recovered: true,
                reason: None,
            },
            reason: None,
        }
    }

    #[test]
    fn success_requires_live_survive_and_running_reattach() {
        let report = complete_report();
        assert!(report.is_success());

        let mut reaped = report.clone();
        reaped.recovery.live_vm_processes_reaped = true;
        assert!(!reaped.is_success());

        let mut stopped = report.clone();
        stopped.recovery.replacement_state_running = false;
        assert!(!stopped.is_success());

        let mut invented = report.clone();
        invented.recovery.no_invented_exit_status = false;
        assert!(!invented.is_success());

        let mut changed_init = report.clone();
        changed_init.recovery.init_pid_after = Some(2);
        changed_init.recovery.init_identity_unchanged = false;
        assert!(!changed_init.is_success());

        let mut not_durable = report.clone();
        not_durable.recovery.session_owner_mode_durable = false;
        assert!(!not_durable.is_success());

        let mut no_io = report.clone();
        no_io.recovery.retained_exec_io_proven = false;
        no_io.recovery.write_stdin_after_reattach = false;
        assert!(!no_io.is_success());

        let mut no_new_exec = report.clone();
        no_new_exec.recovery.new_exec_io_after_reattach_proven = false;
        assert!(!no_new_exec.is_success());

        let mut missing_new_id = report.clone();
        missing_new_id.recovery.new_exec_process_id = None;
        assert!(!missing_new_id.is_success());

        let mut no_fs = report;
        no_fs.recovery.retained_filesystem_proven = false;
        no_fs.recovery.file_download_after_reattach = false;
        assert!(!no_fs.is_success());
    }
}
