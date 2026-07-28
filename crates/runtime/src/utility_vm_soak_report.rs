use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

/// Schema emitted by the macOS HVF utility-VM soak diagnostic.
pub const MACOS_HVF_SOAK_SCHEMA_VERSION: &str = "a3s.oci.macos-hvf-soak.v1";

/// Fixed number of primary containers kept live inside every soak VM.
pub const MACOS_HVF_SOAK_CONCURRENT_CONTAINERS: u32 = 2;
/// Upper bound for one invocation. Operators can retain multiple reports.
pub const MAX_MACOS_HVF_SOAK_ITERATIONS: u32 = 10_000;

/// Bounded configuration retained in every macOS HVF soak report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHvfSoakConfig {
    /// Number of complete utility-VM waves.
    pub iterations: u32,
    /// Primary containers kept live together inside every VM.
    pub concurrent_containers: u32,
}

impl MacosHvfSoakConfig {
    /// Construct the fixed two-container soak profile.
    #[must_use]
    pub const fn new(iterations: u32) -> Self {
        Self {
            iterations,
            concurrent_containers: MACOS_HVF_SOAK_CONCURRENT_CONTAINERS,
        }
    }

    /// Reject empty, unbounded, or structurally altered profiles.
    pub fn validate(&self) -> Result<(), String> {
        if self.iterations == 0 || self.iterations > MAX_MACOS_HVF_SOAK_ITERATIONS {
            return Err(format!(
                "macOS HVF soak iterations must be between 1 and \
                 {MAX_MACOS_HVF_SOAK_ITERATIONS}"
            ));
        }
        if self.concurrent_containers != MACOS_HVF_SOAK_CONCURRENT_CONTAINERS {
            return Err(format!(
                "macOS HVF soak requires exactly \
                 {MACOS_HVF_SOAK_CONCURRENT_CONTAINERS} concurrent containers"
            ));
        }
        Ok(())
    }

    /// Primary container generations qualified by the repeated lifecycle.
    ///
    /// Every wave creates both primary containers and recreates the first at
    /// its next generation. Namespace-join and mount-profile helper
    /// containers are deliberately additional to this conservative count.
    #[must_use]
    pub const fn expected_primary_container_generations(&self) -> u64 {
        self.iterations as u64 * 3
    }
}

impl Default for MacosHvfSoakConfig {
    fn default() -> Self {
        Self::new(25)
    }
}

/// Retained evidence for repeated macOS HVF utility-VM lifecycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHvfSoakReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the configured soak profile.
    pub status: CapabilityStatus,
    /// Exact bounded configuration used by this invocation.
    pub configuration: MacosHvfSoakConfig,
    /// Fully cleaned waves completed before the report was emitted.
    pub completed_iterations: u32,
    /// Complete libkrun/HVF VM sessions that returned to baseline.
    pub completed_vm_lifecycles: u32,
    /// Initial A/B plus recreated-A generations qualified across all waves.
    pub completed_primary_container_generations: u64,
    /// Whether every wave completed the exact lifecycle and generation matrix.
    pub lifecycle_verified_every_iteration: bool,
    /// Whether every wave completed existing-namespace join enforcement.
    pub namespace_join_verified_every_iteration: bool,
    /// Whether every wave completed rootfs and mount enforcement.
    pub rootfs_mount_verified_every_iteration: bool,
    /// Whether every wave completed namespace PID 1 and orphan reaping checks.
    pub pid_supervision_verified_every_iteration: bool,
    /// Whether workload markers were removed after every VM shutdown.
    pub markers_removed_every_iteration: bool,
    /// Whether every VM shutdown restored the guest runtime directory baseline.
    pub guest_runtime_clean_every_iteration: bool,
    /// Whether every endpoint, shim, VM worker, and descriptor inventory was restored.
    pub host_cleanup_verified_every_iteration: bool,
    /// Whether every successful wave used a distinct protected host endpoint.
    pub unique_endpoint_names: bool,
    /// Host descriptor count before the first successful wave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steady_open_descriptors: Option<u32>,
    /// Host descriptor count after the final successful wave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_open_descriptors: Option<u32>,
    /// Whether every wave began and ended with the same descriptor count.
    pub descriptor_count_stable: bool,
    /// Per-wave console files created by libkrun.
    pub console_files_created: u32,
    /// One-based wave that failed or timed out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_iteration: Option<u32>,
    /// Diagnostic reason when the soak did not complete successfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MacosHvfSoakReport {
    pub(crate) fn initial(platform: HostPlatform, configuration: MacosHvfSoakConfig) -> Self {
        Self {
            schema_version: MACOS_HVF_SOAK_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            configuration,
            completed_iterations: 0,
            completed_vm_lifecycles: 0,
            completed_primary_container_generations: 0,
            lifecycle_verified_every_iteration: true,
            namespace_join_verified_every_iteration: true,
            rootfs_mount_verified_every_iteration: true,
            pid_supervision_verified_every_iteration: true,
            markers_removed_every_iteration: true,
            guest_runtime_clean_every_iteration: true,
            host_cleanup_verified_every_iteration: true,
            unique_endpoint_names: true,
            steady_open_descriptors: None,
            final_open_descriptors: None,
            descriptor_count_stable: true,
            console_files_created: 0,
            failure_iteration: None,
            reason: None,
        }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported(platform: HostPlatform, configuration: MacosHvfSoakConfig) -> Self {
        let mut report = Self::initial(platform, configuration);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("the macOS HVF soak requires Apple Silicon and libkrun/HVF".into());
        report
    }

    /// Return whether every configured VM, container, and cleanup invariant passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.evidence_succeeded()
            && self.failure_iteration.is_none()
            && self.reason.is_none()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.platform == HostPlatform::Macos
            && self.configuration.validate().is_ok()
            && self.completed_iterations == self.configuration.iterations
            && self.completed_vm_lifecycles == self.configuration.iterations
            && self.completed_primary_container_generations
                == self.configuration.expected_primary_container_generations()
            && self.lifecycle_verified_every_iteration
            && self.namespace_join_verified_every_iteration
            && self.rootfs_mount_verified_every_iteration
            && self.pid_supervision_verified_every_iteration
            && self.markers_removed_every_iteration
            && self.guest_runtime_clean_every_iteration
            && self.host_cleanup_verified_every_iteration
            && self.unique_endpoint_names
            && self.steady_open_descriptors.is_some_and(|count| count > 0)
            && self.final_open_descriptors == self.steady_open_descriptors
            && self.descriptor_count_stable
            && self.console_files_created == self.configuration.iterations
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::{CapabilityStatus, HostPlatform};

    use super::{MacosHvfSoakConfig, MacosHvfSoakReport, MAX_MACOS_HVF_SOAK_ITERATIONS};

    #[test]
    fn configuration_rejects_empty_unbounded_or_altered_profiles() {
        assert!(MacosHvfSoakConfig::new(0).validate().is_err());
        assert!(MacosHvfSoakConfig::new(MAX_MACOS_HVF_SOAK_ITERATIONS + 1)
            .validate()
            .is_err());
        let mut altered = MacosHvfSoakConfig::new(1);
        altered.concurrent_containers = 3;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn success_requires_every_wave_and_cleanup_invariant() {
        let configuration = MacosHvfSoakConfig::new(25);
        let mut report = MacosHvfSoakReport::initial(HostPlatform::Macos, configuration);
        report.status = CapabilityStatus::Available;
        report.completed_iterations = 25;
        report.completed_vm_lifecycles = 25;
        report.completed_primary_container_generations = 75;
        report.steady_open_descriptors = Some(8);
        report.final_open_descriptors = Some(8);
        report.console_files_created = 25;
        assert!(report.is_success());

        report.descriptor_count_stable = false;
        assert!(!report.is_success());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    #[test]
    fn unsupported_report_retains_configuration_and_fails_closed() {
        let configuration = MacosHvfSoakConfig::new(7);
        let report = MacosHvfSoakReport::unsupported(HostPlatform::Linux, configuration);
        assert_eq!(report.configuration, configuration);
        assert!(!report.is_success());
    }
}
