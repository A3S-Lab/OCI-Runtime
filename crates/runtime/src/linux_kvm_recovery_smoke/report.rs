use std::path::PathBuf;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerTarget, ExitStatus};
use serde::{Deserialize, Serialize};

pub const LINUX_KVM_RECOVERY_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.linux-kvm-recovery-smoke.v1";

/// Exact Linux process incarnation retained across owner death.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LinuxProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub start_time_ticks: u64,
    pub command: String,
}

/// Immutable inputs bound to one recovery qualification report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKvmRecoveryArtifacts {
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

impl LinuxKvmRecoveryArtifacts {
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

/// Owner-SIGKILL, authenticated recovery, and replacement-service evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKvmRecoveryEvidence {
    pub qualification_scope_verified: bool,
    pub first_host_service: Option<LinuxProcessIdentity>,
    pub first_socket_peer: Option<LinuxProcessIdentity>,
    pub target: Option<ContainerTarget>,
    pub created_config_digest: Option<String>,
    pub create_replayed: bool,
    pub start_returned_running: bool,
    pub init_marker_verified: bool,
    pub live_vm_processes: Vec<LinuxProcessIdentity>,
    pub authenticated_endpoint_consumed: bool,
    pub host_service_sigkill_delivered: bool,
    pub first_host_service_reaped: bool,
    pub stale_socket_retained: bool,
    pub live_vm_processes_reaped: bool,
    pub endpoint_inventory_restored: bool,
    pub authenticated_recovery_report_retained: bool,
    pub replacement_host_service: Option<LinuxProcessIdentity>,
    pub replacement_socket_peer: Option<LinuxProcessIdentity>,
    pub replacement_socket_new_owner: bool,
    pub replacement_connected: bool,
    pub exact_stopped_state_recovered: bool,
    pub process_inventory_empty: bool,
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
    pub console_files_retained: u32,
    pub replacement_socket_removed: bool,
    pub replacement_exit_success: bool,
    pub service_restart_recovered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LinuxKvmRecoveryEvidence {
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.qualification_scope_verified
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
            && self.live_vm_processes.len() >= 2
            && self.authenticated_endpoint_consumed
            && self.host_service_sigkill_delivered
            && self.first_host_service_reaped
            && self.stale_socket_retained
            && self.live_vm_processes_reaped
            && self.endpoint_inventory_restored
            && self.authenticated_recovery_report_retained
            && self.replacement_host_service.is_some()
            && self.replacement_socket_peer == self.replacement_host_service
            && self.first_socket_peer != self.replacement_socket_peer
            && self.replacement_socket_new_owner
            && self.replacement_connected
            && self.exact_stopped_state_recovered
            && self.process_inventory_empty
            && self.recovered_wait_status == ExitStatus::signaled(libc::SIGKILL, false).ok()
            && self.recovered_wait_replayed
            && self.stopped_delete_succeeded
            && self.durable_state_removed
            && self.replacement_descriptor_inventory_restored
            && self.open_descriptors_before == self.open_descriptors_after
            && self.bundle_handoffs_clean
            && self.runtime_shares_clean
            && self.recovery_reports_clean
            && self.console_files_retained >= 1
            && self.replacement_socket_removed
            && self.replacement_exit_success
            && self.service_restart_recovered
            && self.reason.is_none()
    }
}

/// Complete Linux KVM owner-death and Host Service restart report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKvmRecoverySmokeReport {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub architecture: String,
    pub kvm_required: bool,
    pub expected_case_count: u32,
    pub case_count: u32,
    pub evidence_root: PathBuf,
    pub artifacts: LinuxKvmRecoveryArtifacts,
    pub recovery: LinuxKvmRecoveryEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LinuxKvmRecoverySmokeReport {
    pub(super) fn initial(evidence_root: PathBuf, architecture: String) -> Self {
        Self {
            schema_version: LINUX_KVM_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            platform: HostPlatform::Linux,
            architecture,
            kvm_required: true,
            expected_case_count: 1,
            case_count: 0,
            evidence_root,
            artifacts: LinuxKvmRecoveryArtifacts::default(),
            recovery: LinuxKvmRecoveryEvidence::default(),
            reason: None,
        }
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        self.schema_version == LINUX_KVM_RECOVERY_SMOKE_SCHEMA_VERSION
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
    use a3s_oci_sdk::{ContainerId, Generation};

    use super::*;

    fn process(pid: u32, parent_pid: u32) -> LinuxProcessIdentity {
        LinuxProcessIdentity {
            pid,
            parent_pid,
            process_group_id: pid,
            start_time_ticks: u64::from(pid) * 10,
            command: "a3s-oci".to_string(),
        }
    }

    fn complete_report() -> LinuxKvmRecoverySmokeReport {
        let first = process(101, 100);
        let replacement = process(201, 100);
        LinuxKvmRecoverySmokeReport {
            schema_version: LINUX_KVM_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
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
            recovery: LinuxKvmRecoveryEvidence {
                qualification_scope_verified: true,
                first_host_service: Some(first.clone()),
                first_socket_peer: Some(first),
                target: Some(ContainerTarget::exact(
                    ContainerId::new("kvm-recovery").expect("container ID"),
                    Generation(1),
                )),
                created_config_digest: Some(format!("sha256:{}", "6".repeat(64))),
                create_replayed: true,
                start_returned_running: true,
                init_marker_verified: true,
                live_vm_processes: vec![process(102, 101), process(103, 102)],
                authenticated_endpoint_consumed: true,
                host_service_sigkill_delivered: true,
                first_host_service_reaped: true,
                stale_socket_retained: true,
                live_vm_processes_reaped: true,
                endpoint_inventory_restored: true,
                authenticated_recovery_report_retained: true,
                replacement_host_service: Some(replacement.clone()),
                replacement_socket_peer: Some(replacement),
                replacement_socket_new_owner: true,
                replacement_connected: true,
                exact_stopped_state_recovered: true,
                process_inventory_empty: true,
                recovered_wait_status: ExitStatus::signaled(libc::SIGKILL, false).ok(),
                recovered_wait_replayed: true,
                stopped_delete_succeeded: true,
                durable_state_removed: true,
                replacement_descriptor_inventory_restored: true,
                open_descriptors_before: Some(12),
                open_descriptors_after: Some(12),
                bundle_handoffs_clean: true,
                runtime_shares_clean: true,
                recovery_reports_clean: true,
                console_files_retained: 1,
                replacement_socket_removed: true,
                replacement_exit_success: true,
                service_restart_recovered: true,
                reason: None,
            },
            reason: None,
        }
    }

    #[test]
    fn success_requires_exact_owner_replacement_and_cleanup() {
        let report = complete_report();
        assert!(report.is_success());

        let mut same_owner = report.clone();
        same_owner.recovery.replacement_host_service =
            same_owner.recovery.first_host_service.clone();
        same_owner.recovery.replacement_socket_peer = same_owner.recovery.first_socket_peer.clone();
        assert!(!same_owner.is_success());

        let mut invented_wait = report.clone();
        invented_wait.recovery.recovered_wait_status = ExitStatus::exited(0).ok();
        assert!(!invented_wait.is_success());

        let mut leaked = report;
        leaked.recovery.runtime_shares_clean = false;
        assert!(!leaked.is_success());
    }
}
