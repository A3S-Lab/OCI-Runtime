use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerTarget, ExitStatus};
use serde::{Deserialize, Serialize};

use super::report::{canonical_sha256_digest, LinuxKvmRecoveryArtifacts, LinuxProcessIdentity};

pub const LINUX_KVM_SOAK_SCHEMA_VERSION: &str = "a3s.oci.linux-kvm-soak.v1";
pub const DEFAULT_LINUX_KVM_SOAK_ITERATIONS: u32 = 25;
pub const MAX_LINUX_KVM_SOAK_ITERATIONS: u32 = 1_000;

/// Retained evidence for one fresh KVM generation in a bounded soak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKvmSoakWaveEvidence {
    pub iteration: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<ContainerTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_cgroups_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_config_digest: Option<String>,
    pub create_replayed: bool,
    pub generation_monotonic: bool,
    pub stale_generation_rejected: bool,
    pub start_returned_running: bool,
    pub init_marker_verified: bool,
    pub live_vm_processes: Vec<LinuxProcessIdentity>,
    pub kill_replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_status: Option<ExitStatus>,
    pub wait_replayed: bool,
    pub delete_replayed: bool,
    pub state_removed: bool,
    pub source_marker_absent: bool,
    pub vm_processes_reaped: bool,
    pub endpoint_inventory_restored: bool,
    pub descriptor_inventory_restored: bool,
    pub bundle_handoffs_clean: bool,
    pub runtime_shares_clean: bool,
    pub recovery_reports_clean: bool,
    /// Guest cgroups disappear with the reaped per-generation VM kernel.
    pub guest_cgroup_lifetime_bounded: bool,
    pub console_files_retained: u32,
}

impl LinuxKvmSoakWaveEvidence {
    pub(super) fn initial(iteration: u32, cgroups_path: &Path) -> Self {
        Self {
            iteration,
            target: None,
            configured_cgroups_path: Some(cgroups_path.to_path_buf()),
            created_config_digest: None,
            create_replayed: false,
            generation_monotonic: false,
            stale_generation_rejected: false,
            start_returned_running: false,
            init_marker_verified: false,
            live_vm_processes: Vec::new(),
            kill_replayed: false,
            wait_status: None,
            wait_replayed: false,
            delete_replayed: false,
            state_removed: false,
            source_marker_absent: false,
            vm_processes_reaped: false,
            endpoint_inventory_restored: false,
            descriptor_inventory_restored: false,
            bundle_handoffs_clean: false,
            runtime_shares_clean: false,
            recovery_reports_clean: false,
            guest_cgroup_lifetime_bounded: false,
            console_files_retained: 0,
        }
    }

    fn is_success(&self, expected_iteration: u32, expected_cgroups_path: &Path) -> bool {
        self.iteration == expected_iteration
            && self.target.as_ref().is_some_and(|target| {
                target
                    .generation
                    .is_some_and(|generation| generation.0 == u64::from(expected_iteration))
            })
            && self.configured_cgroups_path.as_deref() == Some(expected_cgroups_path)
            && self
                .created_config_digest
                .as_deref()
                .is_some_and(canonical_sha256_digest)
            && self.create_replayed
            && self.generation_monotonic
            && self.stale_generation_rejected
            && self.start_returned_running
            && self.init_marker_verified
            && self.live_vm_processes.len() >= 2
            && self.kill_replayed
            && self.wait_status == ExitStatus::signaled(libc::SIGKILL, false).ok()
            && self.wait_replayed
            && self.delete_replayed
            && self.state_removed
            && self.source_marker_absent
            && self.vm_processes_reaped
            && self.endpoint_inventory_restored
            && self.descriptor_inventory_restored
            && self.bundle_handoffs_clean
            && self.runtime_shares_clean
            && self.recovery_reports_clean
            && self.guest_cgroup_lifetime_bounded
            && self.console_files_retained >= expected_iteration
    }
}

/// Bounded real-host KVM soak report retained independently per architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKvmSoakReport {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub architecture: String,
    pub kvm_required: bool,
    pub requested_iterations: u32,
    pub evidence_root: PathBuf,
    pub artifacts: LinuxKvmRecoveryArtifacts,
    pub qualification_scope_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_service: Option<LinuxProcessIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_peer: Option<LinuxProcessIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_cgroups_path: Option<PathBuf>,
    pub waves: Vec<LinuxKvmSoakWaveEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steady_open_descriptors: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_open_descriptors: Option<u32>,
    pub console_files_created: u32,
    pub service_socket_removed: bool,
    pub service_exit_success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_iteration: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LinuxKvmSoakReport {
    pub(super) fn initial(
        evidence_root: PathBuf,
        architecture: String,
        requested_iterations: u32,
    ) -> Self {
        Self {
            schema_version: LINUX_KVM_SOAK_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            platform: HostPlatform::Linux,
            architecture,
            kvm_required: true,
            requested_iterations,
            evidence_root,
            artifacts: LinuxKvmRecoveryArtifacts::default(),
            qualification_scope_verified: false,
            host_service: None,
            socket_peer: None,
            source_cgroups_path: None,
            waves: Vec::new(),
            steady_open_descriptors: None,
            final_open_descriptors: None,
            console_files_created: 0,
            service_socket_removed: false,
            service_exit_success: false,
            failure_iteration: None,
            reason: None,
        }
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        let Some(cgroups_path) = self.source_cgroups_path.as_deref() else {
            return false;
        };
        let mut process_incarnations = BTreeSet::new();
        let waves_are_complete = self.waves.len()
            == usize::try_from(self.requested_iterations).unwrap_or(usize::MAX)
            && self.waves.iter().enumerate().all(|(index, wave)| {
                let expected_iteration = u32::try_from(index + 1).unwrap_or(u32::MAX);
                wave.is_success(expected_iteration, cgroups_path)
                    && wave.live_vm_processes.iter().all(|process| {
                        process_incarnations.insert((process.pid, process.start_time_ticks))
                    })
            });

        self.schema_version == LINUX_KVM_SOAK_SCHEMA_VERSION
            && self.status == CapabilityStatus::Available
            && self.platform == HostPlatform::Linux
            && matches!(self.architecture.as_str(), "x86_64" | "aarch64")
            && self.kvm_required
            && validate_iterations(self.requested_iterations).is_ok()
            && self.evidence_root.is_absolute()
            && self.artifacts.is_complete()
            && self.qualification_scope_verified
            && self.host_service.is_some()
            && self.socket_peer == self.host_service
            && valid_cgroups_path(cgroups_path)
            && waves_are_complete
            && self.steady_open_descriptors.is_some_and(|count| count > 0)
            && self.final_open_descriptors == self.steady_open_descriptors
            && self.console_files_created >= self.requested_iterations
            && self.service_socket_removed
            && self.service_exit_success
            && self.failure_iteration.is_none()
            && self.reason.is_none()
    }
}

pub(super) fn validate_iterations(iterations: u32) -> Result<(), String> {
    if iterations == 0 || iterations > MAX_LINUX_KVM_SOAK_ITERATIONS {
        return Err(format!(
            "Linux KVM soak iterations must be between 1 and {MAX_LINUX_KVM_SOAK_ITERATIONS}"
        ));
    }
    Ok(())
}

fn valid_cgroups_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path.components().all(|component| {
            matches!(
                component,
                Component::RootDir | Component::Normal(_) | Component::CurDir
            )
        })
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation};

    use super::*;

    fn process(pid: u32) -> LinuxProcessIdentity {
        LinuxProcessIdentity {
            pid,
            parent_pid: 10,
            process_group_id: pid,
            start_time_ticks: u64::from(pid) * 100,
            command: "a3s-oci-krun".to_string(),
        }
    }

    fn wave(iteration: u32, first_pid: u32) -> LinuxKvmSoakWaveEvidence {
        LinuxKvmSoakWaveEvidence {
            iteration,
            target: Some(ContainerTarget::exact(
                ContainerId::new("kvm-soak").expect("container ID"),
                Generation(u64::from(iteration)),
            )),
            configured_cgroups_path: Some(PathBuf::from("a3s-oci-kvm-soak")),
            created_config_digest: Some(format!("sha256:{}", "6".repeat(64))),
            create_replayed: true,
            generation_monotonic: true,
            stale_generation_rejected: true,
            start_returned_running: true,
            init_marker_verified: true,
            live_vm_processes: vec![process(first_pid), process(first_pid + 1)],
            kill_replayed: true,
            wait_status: ExitStatus::signaled(libc::SIGKILL, false).ok(),
            wait_replayed: true,
            delete_replayed: true,
            state_removed: true,
            source_marker_absent: true,
            vm_processes_reaped: true,
            endpoint_inventory_restored: true,
            descriptor_inventory_restored: true,
            bundle_handoffs_clean: true,
            runtime_shares_clean: true,
            recovery_reports_clean: true,
            guest_cgroup_lifetime_bounded: true,
            console_files_retained: iteration,
        }
    }

    fn complete_report() -> LinuxKvmSoakReport {
        let service = process(100);
        LinuxKvmSoakReport {
            schema_version: LINUX_KVM_SOAK_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Available,
            platform: HostPlatform::Linux,
            architecture: "aarch64".to_string(),
            kvm_required: true,
            requested_iterations: 2,
            evidence_root: PathBuf::from("/tmp/kvm-soak"),
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
            qualification_scope_verified: true,
            host_service: Some(service.clone()),
            socket_peer: Some(service),
            source_cgroups_path: Some(PathBuf::from("a3s-oci-kvm-soak")),
            waves: vec![wave(1, 200), wave(2, 300)],
            steady_open_descriptors: Some(12),
            final_open_descriptors: Some(12),
            console_files_created: 2,
            service_socket_removed: true,
            service_exit_success: true,
            failure_iteration: None,
            reason: None,
        }
    }

    #[test]
    fn success_requires_every_wave_and_unique_process_incarnation() {
        let report = complete_report();
        assert!(report.is_success());

        let mut reused = report.clone();
        reused.waves[1].live_vm_processes = reused.waves[0].live_vm_processes.clone();
        assert!(!reused.is_success());

        let mut leaked = report;
        leaked.waves[1].guest_cgroup_lifetime_bounded = false;
        assert!(!leaked.is_success());
    }

    #[test]
    fn iteration_count_is_bounded() {
        assert!(validate_iterations(0).is_err());
        assert!(validate_iterations(DEFAULT_LINUX_KVM_SOAK_ITERATIONS).is_ok());
        assert!(validate_iterations(MAX_LINUX_KVM_SOAK_ITERATIONS + 1).is_err());
    }
}
