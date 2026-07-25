use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ExitStatus, RuntimeOperation};
use serde::{Deserialize, Serialize};

use crate::AgentVmSmokeReport;

/// Schema emitted by the native Linux multi-container lifecycle diagnostic.
pub const NATIVE_LINUX_MULTI_CONTAINER_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-multi-container-smoke.v2";
/// Schema emitted by the utility-VM multi-container lifecycle diagnostic.
pub const OCI_VM_MULTI_CONTAINER_SCHEMA_VERSION: &str = "a3s.oci.oci-vm-multi-container-smoke.v2";

/// Exact multi-container lifecycle and isolation evidence shared by both paths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiContainerLifecycleEvidence {
    /// Whether the two submitted bundles resolved to different directories.
    pub distinct_bundle_directories: bool,
    /// Whether the bundles resolved to different container root filesystems.
    pub distinct_rootfs_directories: bool,
    /// Whether both creates reached the OCI `created` barrier before either start.
    pub both_created_before_start: bool,
    /// First generation allocated to container A.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_generation_a: Option<u64>,
    /// First generation allocated to container B.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_generation_b: Option<u64>,
    /// Generation allocated when container A was recreated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recreated_generation_a: Option<u64>,
    /// Initial host- or guest-visible PID for container A.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid_a: Option<i32>,
    /// Host- or guest-visible PID for container B.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid_b: Option<i32>,
    /// Whether both initial PIDs were positive and distinct.
    pub distinct_created_pids: bool,
    /// Whether both create mutations replayed their exact original results.
    pub create_replays_exact: bool,
    /// Whether neither workload marker existed before the first start.
    pub both_markers_absent_before_start: bool,
    /// Whether starting container A replayed exactly.
    pub start_a_replayed: bool,
    /// Whether container A produced its exact marker after start.
    pub marker_a_verified: bool,
    /// Whether container B remained at the same created barrier after A started.
    pub b_unchanged_after_a_start: bool,
    /// Whether container B's marker remained absent after A started.
    pub marker_b_absent_after_a_start: bool,
    /// Whether waiting on running container A left container B independently queryable.
    pub wait_a_did_not_block_b: bool,
    /// Whether killing container A replayed exactly.
    pub kill_a_replayed: bool,
    /// Whether container A was observed stopped.
    pub a_stopped: bool,
    /// Exact terminal result returned for container A.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_status_a: Option<ExitStatus>,
    /// Whether repeated wait for container A returned the same result.
    pub wait_a_replayed: bool,
    /// Whether container B remained at the same created barrier after A was killed.
    pub b_unchanged_after_a_kill: bool,
    /// Whether container B's marker remained absent after A was killed.
    pub marker_b_absent_after_a_kill: bool,
    /// Whether deleting the first generation of A replayed exactly.
    pub delete_a_replayed: bool,
    /// Whether the deleted first generation of A became unobservable.
    pub a_missing_after_delete: bool,
    /// Whether container B remained unchanged after A was deleted.
    pub b_unchanged_after_a_delete: bool,
    /// Whether a stale first-generation request for A was rejected.
    pub stale_generation_rejected: bool,
    /// Whether recreating A allocated exactly the next generation.
    pub generation_a_monotonic: bool,
    /// Whether recreating container A replayed its exact result.
    pub recreate_a_replayed: bool,
    /// Whether recreated A remained behind the start barrier.
    pub marker_a_absent_after_recreate: bool,
    /// Whether reusing A's operation ID for B was rejected without mutation.
    pub cross_container_operation_rejected: bool,
    /// Whether B remained unchanged after the cross-container replay conflict.
    pub b_unchanged_after_replay_conflict: bool,
    /// Whether recreated A was removed without altering B.
    pub recreated_a_deleted: bool,
    /// Whether starting container B replayed exactly.
    pub start_b_replayed: bool,
    /// Whether container B produced its exact marker after start.
    pub marker_b_verified: bool,
    /// Whether killing container B replayed exactly.
    pub kill_b_replayed: bool,
    /// Whether container B was observed stopped.
    pub b_stopped: bool,
    /// Exact terminal result returned for container B.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_status_b: Option<ExitStatus>,
    /// Whether repeated wait for container B returned the same result.
    pub wait_b_replayed: bool,
    /// Whether deleting container B replayed exactly.
    pub delete_b_replayed: bool,
    /// Whether container B became unobservable after delete.
    pub b_missing_after_delete: bool,
}

impl MultiContainerLifecycleEvidence {
    /// Return whether every fixed multi-container invariant was proven.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.distinct_bundle_directories
            && self.distinct_rootfs_directories
            && self.both_created_before_start
            && self.initial_generation_a == Some(1)
            && self.initial_generation_b == Some(1)
            && self.recreated_generation_a == Some(2)
            && self.created_pid_a.is_some_and(|pid| pid > 0)
            && self.created_pid_b.is_some_and(|pid| pid > 0)
            && self.distinct_created_pids
            && self.create_replays_exact
            && self.both_markers_absent_before_start
            && self.start_a_replayed
            && self.marker_a_verified
            && self.b_unchanged_after_a_start
            && self.marker_b_absent_after_a_start
            && self.wait_a_did_not_block_b
            && self.kill_a_replayed
            && self.a_stopped
            && self
                .wait_status_a
                .as_ref()
                .is_some_and(|status| status.validate().is_ok())
            && self.wait_a_replayed
            && self.b_unchanged_after_a_kill
            && self.marker_b_absent_after_a_kill
            && self.delete_a_replayed
            && self.a_missing_after_delete
            && self.b_unchanged_after_a_delete
            && self.stale_generation_rejected
            && self.generation_a_monotonic
            && self.recreate_a_replayed
            && self.marker_a_absent_after_recreate
            && self.cross_container_operation_rejected
            && self.b_unchanged_after_replay_conflict
            && self.recreated_a_deleted
            && self.start_b_replayed
            && self.marker_b_verified
            && self.kill_b_replayed
            && self.b_stopped
            && self
                .wait_status_b
                .as_ref()
                .is_some_and(|status| status.validate().is_ok())
            && self.wait_status_a == self.wait_status_b
            && self.wait_b_replayed
            && self.delete_b_replayed
            && self.b_missing_after_delete
    }
}

/// End-to-end evidence for two native Linux containers sharing one executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxMultiContainerSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the diagnostic path.
    pub status: CapabilityStatus,
    /// Whether `/dev/kvm` existed while the independent native path ran.
    pub kvm_device_present: bool,
    /// Whether both submitted OCI bundles loaded successfully.
    pub bundles_loaded: bool,
    /// Operations advertised by the explicitly opened native service.
    pub service_operations: Vec<RuntimeOperation>,
    /// Per-container generation, replay, isolation, and lifecycle evidence.
    pub lifecycle: MultiContainerLifecycleEvidence,
    /// Whether both workload markers were removed.
    pub markers_removed: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the diagnostic removed its durable and transient workspace.
    pub session_root_clean: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxMultiContainerSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: NATIVE_LINUX_MULTI_CONTAINER_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            kvm_device_present: false,
            bundles_loaded: false,
            service_operations: Vec::new(),
            lifecycle: MultiContainerLifecycleEvidence::default(),
            markers_removed: false,
            executor_runtime_clean: false,
            session_root_clean: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("the native multi-container diagnostic requires a Linux host".into());
        report
    }

    /// Return whether all native lifecycle and cleanup evidence passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.evidence_succeeded()
            && self.reason.is_none()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.bundles_loaded
            && self.service_operations
                == [
                    RuntimeOperation::Features,
                    RuntimeOperation::Create,
                    RuntimeOperation::State,
                    RuntimeOperation::Start,
                    RuntimeOperation::Kill,
                    RuntimeOperation::Delete,
                    RuntimeOperation::Wait,
                ]
            && self.lifecycle.is_success()
            && self.lifecycle.wait_status_a
                == Some(ExitStatus {
                    exit_code: None,
                    signal: Some(9),
                    oom_killed: false,
                })
            && self.lifecycle.wait_status_b == self.lifecycle.wait_status_a
            && self.markers_removed
            && self.executor_runtime_clean
            && self.session_root_clean
    }
}

/// End-to-end evidence for two containers inside one authenticated utility VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmMultiContainerSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the diagnostic path.
    pub status: CapabilityStatus,
    /// Whether both submitted OCI bundles loaded successfully.
    pub bundles_loaded: bool,
    /// Per-container generation, replay, isolation, and lifecycle evidence.
    pub lifecycle: MultiContainerLifecycleEvidence,
    /// Whether both workload markers were removed.
    pub markers_removed: bool,
    /// Whether VM shutdown left no new guest-agent runtime directory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated host/guest and shim evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmMultiContainerSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: OCI_VM_MULTI_CONTAINER_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundles_loaded: false,
            lifecycle: MultiContainerLifecycleEvidence::default(),
            markers_removed: false,
            guest_runtime_clean: false,
            bridge: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.bridge.status = CapabilityStatus::Unsupported;
        report.bridge.reason = Some("the authenticated guest bridge was not attempted".into());
        report.reason = Some(
            "the utility-VM multi-container diagnostic is implemented only for \
             Windows x86_64/WHPX and macOS aarch64/HVF"
                .into(),
        );
        report
    }

    /// Return whether all utility-VM lifecycle and cleanup evidence passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.evidence_succeeded()
            && self.reason.is_none()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.bundles_loaded
            && self.lifecycle.is_success()
            && self.lifecycle.wait_status_a
                == Some(ExitStatus {
                    exit_code: Some(0),
                    signal: None,
                    oom_killed: false,
                })
            && self.lifecycle.wait_status_b == self.lifecycle.wait_status_a
            && self.markers_removed
            && self.guest_runtime_clean
            && self.bridge.is_success()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::ExitStatus;

    use super::MultiContainerLifecycleEvidence;

    #[test]
    fn multi_container_success_requires_every_isolation_invariant() {
        let complete = complete_lifecycle();
        assert!(complete.is_success());

        let mut incomplete = complete;
        incomplete.b_unchanged_after_a_delete = false;
        assert!(!incomplete.is_success());
    }

    fn complete_lifecycle() -> MultiContainerLifecycleEvidence {
        MultiContainerLifecycleEvidence {
            distinct_bundle_directories: true,
            distinct_rootfs_directories: true,
            both_created_before_start: true,
            initial_generation_a: Some(1),
            initial_generation_b: Some(1),
            recreated_generation_a: Some(2),
            created_pid_a: Some(101),
            created_pid_b: Some(202),
            distinct_created_pids: true,
            create_replays_exact: true,
            both_markers_absent_before_start: true,
            start_a_replayed: true,
            marker_a_verified: true,
            b_unchanged_after_a_start: true,
            marker_b_absent_after_a_start: true,
            wait_a_did_not_block_b: true,
            kill_a_replayed: true,
            a_stopped: true,
            wait_status_a: Some(ExitStatus::signaled(9, false).expect("exit status")),
            wait_a_replayed: true,
            b_unchanged_after_a_kill: true,
            marker_b_absent_after_a_kill: true,
            delete_a_replayed: true,
            a_missing_after_delete: true,
            b_unchanged_after_a_delete: true,
            stale_generation_rejected: true,
            generation_a_monotonic: true,
            recreate_a_replayed: true,
            marker_a_absent_after_recreate: true,
            cross_container_operation_rejected: true,
            b_unchanged_after_replay_conflict: true,
            recreated_a_deleted: true,
            start_b_replayed: true,
            marker_b_verified: true,
            kill_b_replayed: true,
            b_stopped: true,
            wait_status_b: Some(ExitStatus::signaled(9, false).expect("exit status")),
            wait_b_replayed: true,
            delete_b_replayed: true,
            b_missing_after_delete: true,
        }
    }
}
