use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::RuntimeOperation;
use serde::{Deserialize, Serialize};

/// Schema emitted by the native Linux complex-container soak diagnostic.
pub const NATIVE_LINUX_SOAK_SCHEMA_VERSION: &str = "a3s.oci.native-linux-soak.v1";

/// Lower bound for a multi-container soak run.
pub const MIN_SOAK_CONCURRENT_CONTAINERS: u32 = 2;
/// Upper bound that prevents an accidental local fork bomb.
pub const MAX_SOAK_CONCURRENT_CONTAINERS: u32 = 32;
/// Upper bound for a single invocation. Operators can run multiple reports.
pub const MAX_SOAK_ITERATIONS: u32 = 10_000;
/// Smallest useful per-operation deadline.
pub const MIN_SOAK_OPERATION_TIMEOUT_MS: u64 = 100;
/// Largest accepted per-operation deadline.
pub const MAX_SOAK_OPERATION_TIMEOUT_MS: u64 = 300_000;

/// Bounded configuration recorded in every soak report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxSoakConfig {
    /// Number of complete create-to-delete waves.
    pub iterations: u32,
    /// Containers kept live together during every wave.
    pub concurrent_containers: u32,
    /// Outer deadline applied independently to every SDK operation.
    pub operation_timeout_ms: u64,
}

impl NativeLinuxSoakConfig {
    /// Construct a configuration. Validation occurs before the diagnostic
    /// touches a bundle or creates runtime state.
    #[must_use]
    pub const fn new(
        iterations: u32,
        concurrent_containers: u32,
        operation_timeout_ms: u64,
    ) -> Self {
        Self {
            iterations,
            concurrent_containers,
            operation_timeout_ms,
        }
    }

    /// Validate bounds and ensure enough distinct bundle slots were supplied.
    pub fn validate(&self, bundle_count: usize) -> Result<(), String> {
        if self.iterations == 0 || self.iterations > MAX_SOAK_ITERATIONS {
            return Err(format!(
                "soak iterations must be between 1 and {MAX_SOAK_ITERATIONS}"
            ));
        }
        if !(MIN_SOAK_CONCURRENT_CONTAINERS..=MAX_SOAK_CONCURRENT_CONTAINERS)
            .contains(&self.concurrent_containers)
        {
            return Err(format!(
                "soak concurrent containers must be between \
                 {MIN_SOAK_CONCURRENT_CONTAINERS} and {MAX_SOAK_CONCURRENT_CONTAINERS}"
            ));
        }
        if !(MIN_SOAK_OPERATION_TIMEOUT_MS..=MAX_SOAK_OPERATION_TIMEOUT_MS)
            .contains(&self.operation_timeout_ms)
        {
            return Err(format!(
                "soak operation timeout must be between \
                 {MIN_SOAK_OPERATION_TIMEOUT_MS} and {MAX_SOAK_OPERATION_TIMEOUT_MS} ms"
            ));
        }
        let required = usize::try_from(self.concurrent_containers)
            .map_err(|_| "soak concurrency does not fit this host".to_string())?;
        if bundle_count < required {
            return Err(format!(
                "soak requires {required} distinct bundles, but only {bundle_count} were supplied"
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn expected_lifecycles(&self) -> u64 {
        self.iterations as u64 * self.concurrent_containers as u64
    }
}

impl Default for NativeLinuxSoakConfig {
    fn default() -> Self {
        Self::new(25, 2, 15_000)
    }
}

/// Successful SDK operation counts accumulated across all soak waves.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxSoakOperationCounts {
    pub features: u64,
    pub create: u64,
    pub state: u64,
    pub start: u64,
    pub list: u64,
    pub exec: u64,
    pub wait_process: u64,
    pub processes: u64,
    pub stats: u64,
    pub pause: u64,
    pub resume: u64,
    pub kill: u64,
    pub wait: u64,
    pub delete: u64,
    pub read_output: u64,
}

impl NativeLinuxSoakOperationCounts {
    /// Total number of successful SDK calls represented by the report.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.features
            + self.create
            + self.state
            + self.start
            + self.list
            + self.exec
            + self.wait_process
            + self.processes
            + self.stats
            + self.pause
            + self.resume
            + self.kill
            + self.wait
            + self.delete
            + self.read_output
    }

    fn covers(&self, config: NativeLinuxSoakConfig, stale_rejections: u64) -> bool {
        let lifecycles = config.expected_lifecycles();
        let iterations = u64::from(config.iterations);
        self.features > iterations
            && self.create == lifecycles
            && self.state >= lifecycles * 3 + stale_rejections
            && self.start == lifecycles
            && self.list >= iterations * 3
            && self.exec == lifecycles
            && self.wait_process == lifecycles
            && self.processes == lifecycles
            && self.stats == lifecycles
            && self.pause == lifecycles
            && self.resume == lifecycles
            && self.kill == lifecycles
            && self.wait == lifecycles
            && self.delete == lifecycles
            && self.read_output >= lifecycles
    }
}

/// End-to-end evidence for repeated, concurrent native Linux lifecycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxSoakReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the diagnostic path.
    pub status: CapabilityStatus,
    /// Exact bounded configuration used by this run.
    pub configuration: NativeLinuxSoakConfig,
    /// Whether `/dev/kvm` existed while the independent native path ran.
    pub kvm_device_present: bool,
    /// Number of distinct bundles loaded for concurrent slots.
    pub bundles_loaded: u32,
    /// Whether every selected bundle and rootfs resolved to a distinct directory.
    pub distinct_bundles_and_rootfs: bool,
    /// Operations advertised by the explicitly opened native service.
    pub service_operations: Vec<RuntimeOperation>,
    /// Fully cleaned waves completed before the report was emitted.
    pub completed_iterations: u32,
    /// Complete create-to-delete container lifecycles.
    pub completed_container_lifecycles: u64,
    /// Successful SDK operations by kind.
    pub operation_counts: NativeLinuxSoakOperationCounts,
    /// Largest live set observed through one service list.
    pub max_live_containers: u32,
    /// Whether every wave used distinct positive PIDs for every live slot.
    pub unique_live_pids: bool,
    /// Whether generations increased by exactly one every time IDs were reused.
    pub generation_sequence_verified: bool,
    /// Number of prior-generation state requests rejected after recreation.
    pub stale_generation_rejections: u64,
    /// Whether every exec returned its exact expected captured output and exit status.
    pub exec_output_verified: bool,
    /// Whether every live container crossed pause and resume durably.
    pub pause_resume_verified: bool,
    /// Number of times the durable host service was dropped and reopened while live.
    pub durable_reopens: u32,
    /// Whether each reopened service recovered the exact paused live set.
    pub durable_recovery_verified: bool,
    /// Whether list returned no containers after every wave.
    pub runtime_empty_after_each_iteration: bool,
    /// Whether the transient executor root was empty after every wave.
    pub executor_empty_after_each_iteration: bool,
    /// Whether workload markers were removed after every wave.
    pub markers_removed_after_each_iteration: bool,
    /// Open descriptor count after the first fully cleaned wave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steady_open_descriptors: Option<u64>,
    /// Open descriptor count after the final fully cleaned wave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_open_descriptors: Option<u64>,
    /// Whether subsequent clean waves returned to the first clean descriptor count.
    pub descriptor_inventory_stable: bool,
    /// Direct child-process count before the first wave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_child_processes: Option<u64>,
    /// Direct child-process count after the final fully cleaned wave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_child_processes: Option<u64>,
    /// Whether every clean wave restored the direct child-process baseline.
    pub child_process_inventory_stable: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the diagnostic removed its durable and transient workspace.
    pub session_root_clean: bool,
    /// Diagnostic reason when the soak was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxSoakReport {
    pub(crate) fn initial(platform: HostPlatform, configuration: NativeLinuxSoakConfig) -> Self {
        Self {
            schema_version: NATIVE_LINUX_SOAK_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            configuration,
            kvm_device_present: false,
            bundles_loaded: 0,
            distinct_bundles_and_rootfs: false,
            service_operations: Vec::new(),
            completed_iterations: 0,
            completed_container_lifecycles: 0,
            operation_counts: NativeLinuxSoakOperationCounts::default(),
            max_live_containers: 0,
            unique_live_pids: true,
            generation_sequence_verified: true,
            stale_generation_rejections: 0,
            exec_output_verified: true,
            pause_resume_verified: true,
            durable_reopens: 0,
            durable_recovery_verified: true,
            runtime_empty_after_each_iteration: true,
            executor_empty_after_each_iteration: true,
            markers_removed_after_each_iteration: true,
            steady_open_descriptors: None,
            final_open_descriptors: None,
            descriptor_inventory_stable: true,
            baseline_child_processes: None,
            final_child_processes: None,
            child_process_inventory_stable: true,
            executor_runtime_clean: false,
            session_root_clean: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(
        platform: HostPlatform,
        configuration: NativeLinuxSoakConfig,
    ) -> Self {
        let mut report = Self::initial(platform, configuration);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("the native complex-container soak requires a Linux host".into());
        report
    }

    /// Return whether all configured lifecycle, recovery, and cleanup evidence passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.evidence_succeeded()
            && self.reason.is_none()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        let expected = self.configuration.expected_lifecycles();
        let expected_stale = u64::from(self.configuration.iterations.saturating_sub(1))
            * u64::from(self.configuration.concurrent_containers);
        self.bundles_loaded == self.configuration.concurrent_containers
            && self.distinct_bundles_and_rootfs
            && !self.service_operations.is_empty()
            && self.completed_iterations == self.configuration.iterations
            && self.completed_container_lifecycles == expected
            && self
                .operation_counts
                .covers(self.configuration, self.stale_generation_rejections)
            && self.max_live_containers == self.configuration.concurrent_containers
            && self.unique_live_pids
            && self.generation_sequence_verified
            && self.stale_generation_rejections == expected_stale
            && self.exec_output_verified
            && self.pause_resume_verified
            && self.durable_reopens == self.configuration.iterations
            && self.durable_recovery_verified
            && self.runtime_empty_after_each_iteration
            && self.executor_empty_after_each_iteration
            && self.markers_removed_after_each_iteration
            && self.steady_open_descriptors.is_some()
            && self.final_open_descriptors == self.steady_open_descriptors
            && self.descriptor_inventory_stable
            && self.baseline_child_processes.is_some()
            && self.final_child_processes == self.baseline_child_processes
            && self.child_process_inventory_stable
            && self.executor_runtime_clean
            && self.session_root_clean
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NativeLinuxSoakConfig, NativeLinuxSoakReport, MAX_SOAK_CONCURRENT_CONTAINERS,
        MAX_SOAK_ITERATIONS,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};

    #[test]
    fn configuration_rejects_unbounded_or_non_concurrent_runs() {
        assert!(NativeLinuxSoakConfig::new(0, 2, 15_000)
            .validate(2)
            .is_err());
        assert!(
            NativeLinuxSoakConfig::new(MAX_SOAK_ITERATIONS + 1, 2, 15_000)
                .validate(2)
                .is_err()
        );
        assert!(NativeLinuxSoakConfig::new(1, 1, 15_000)
            .validate(2)
            .is_err());
        assert!(
            NativeLinuxSoakConfig::new(1, MAX_SOAK_CONCURRENT_CONTAINERS + 1, 15_000)
                .validate(64)
                .is_err()
        );
        assert!(NativeLinuxSoakConfig::new(1, 4, 15_000)
            .validate(3)
            .is_err());
        assert!(NativeLinuxSoakConfig::new(1, 2, 99).validate(2).is_err());
    }

    #[test]
    fn success_requires_every_configured_lifecycle_and_cleanup_invariant() {
        let configuration = NativeLinuxSoakConfig::new(3, 4, 15_000);
        let mut report = NativeLinuxSoakReport::initial(HostPlatform::Linux, configuration);
        let expected = configuration.expected_lifecycles();
        let stale = 8;
        report.status = CapabilityStatus::Available;
        report.bundles_loaded = 4;
        report.distinct_bundles_and_rootfs = true;
        report
            .service_operations
            .push(a3s_oci_sdk::RuntimeOperation::Create);
        report.completed_iterations = 3;
        report.completed_container_lifecycles = expected;
        report.operation_counts.features = 4;
        report.operation_counts.create = expected;
        report.operation_counts.state = expected * 3 + stale;
        report.operation_counts.start = expected;
        report.operation_counts.list = 9;
        report.operation_counts.exec = expected;
        report.operation_counts.wait_process = expected;
        report.operation_counts.processes = expected;
        report.operation_counts.stats = expected;
        report.operation_counts.pause = expected;
        report.operation_counts.resume = expected;
        report.operation_counts.kill = expected;
        report.operation_counts.wait = expected;
        report.operation_counts.delete = expected;
        report.operation_counts.read_output = expected;
        report.max_live_containers = 4;
        report.stale_generation_rejections = stale;
        report.durable_reopens = 3;
        report.steady_open_descriptors = Some(8);
        report.final_open_descriptors = Some(8);
        report.baseline_child_processes = Some(0);
        report.final_child_processes = Some(0);
        report.executor_runtime_clean = true;
        report.session_root_clean = true;
        assert!(report.is_success());

        report.stale_generation_rejections -= 1;
        assert!(!report.is_success());
    }
}
