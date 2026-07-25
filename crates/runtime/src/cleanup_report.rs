use std::fmt;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::RuntimeOperation;
use serde::{Deserialize, Serialize};

use crate::report::AgentVmSmokeReport;

/// Schema emitted by the native Linux fault-cleanup diagnostic.
pub const NATIVE_LINUX_FAULT_CLEANUP_SCHEMA_VERSION: &str = "a3s.oci.native-linux-fault-cleanup.v3";
/// Schema emitted by the utility-VM fault-cleanup diagnostic.
pub const OCI_VM_FAULT_CLEANUP_SCHEMA_VERSION: &str = "a3s.oci.oci-vm-fault-cleanup.v2";

/// Lifecycle boundary after which the cleanup diagnostic interrupts normal flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleFaultPoint {
    /// Interrupt after OCI create returns the blocked init process.
    AfterCreate,
    /// Interrupt after OCI start releases and observes the running workload.
    AfterStart,
    /// Interrupt immediately after OCI kill accepts the signal.
    AfterKill,
}

impl fmt::Display for LifecycleFaultPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AfterCreate => "after-create",
            Self::AfterStart => "after-start",
            Self::AfterKill => "after-kill",
        })
    }
}

/// Retained evidence that the requested lifecycle boundary was interrupted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultInjectionEvidence {
    /// Boundary requested by the diagnostic caller.
    pub requested_fault: LifecycleFaultPoint,
    /// Boundary at which the diagnostic actually interrupted normal flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected_fault: Option<LifecycleFaultPoint>,
    /// Whether OCI create completed successfully.
    pub create_completed: bool,
    /// Whether OCI start completed successfully.
    pub start_completed: bool,
    /// Whether OCI kill accepted the signal.
    pub kill_completed: bool,
    /// Runtime-visible init PID returned by create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether the workload marker was absent behind the create barrier.
    pub marker_absent_after_create: bool,
    /// Whether the started workload produced the exact expected marker.
    pub marker_verified_after_start: bool,
    /// Whether the diagnostic attempted the normal OCI delete operation.
    pub normal_delete_attempted: bool,
}

impl FaultInjectionEvidence {
    pub(crate) const fn initial(requested_fault: LifecycleFaultPoint) -> Self {
        Self {
            requested_fault,
            injected_fault: None,
            create_completed: false,
            start_completed: false,
            kill_completed: false,
            created_pid: None,
            marker_absent_after_create: false,
            marker_verified_after_start: false,
            normal_delete_attempted: false,
        }
    }

    /// Return whether the exact requested interruption boundary was retained.
    #[must_use]
    pub fn is_success(&self) -> bool {
        let exact_prefix = match self.requested_fault {
            LifecycleFaultPoint::AfterCreate => {
                !self.start_completed && !self.kill_completed && !self.marker_verified_after_start
            }
            LifecycleFaultPoint::AfterStart => {
                self.start_completed && !self.kill_completed && self.marker_verified_after_start
            }
            LifecycleFaultPoint::AfterKill => {
                self.start_completed && self.kill_completed && self.marker_verified_after_start
            }
        };
        self.injected_fault == Some(self.requested_fault)
            && self.create_completed
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.marker_absent_after_create
            && !self.normal_delete_attempted
            && exact_prefix
    }
}

/// Cleanup evidence after interrupting the native Linux lifecycle before delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxFaultCleanupReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this cleanup path.
    pub status: CapabilityStatus,
    /// Whether `/dev/kvm` existed during this independent native path.
    pub kvm_device_present: bool,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Operations advertised by the explicitly opened native service.
    pub service_operations: Vec<RuntimeOperation>,
    /// Exact lifecycle prefix and interruption evidence.
    pub lifecycle: FaultInjectionEvidence,
    /// Whether executor shutdown returned successfully.
    pub executor_shutdown_succeeded: bool,
    /// Whether the runtime-visible init PID disappeared after shutdown.
    pub process_reaped: bool,
    /// Whether the known workload marker was absent after cleanup.
    pub marker_removed: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the diagnostic removed its durable and transient workspace.
    pub session_root_clean: bool,
    /// Diagnostic reason when cleanup was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxFaultCleanupReport {
    pub(crate) fn initial(platform: HostPlatform, fault: LifecycleFaultPoint) -> Self {
        Self {
            schema_version: NATIVE_LINUX_FAULT_CLEANUP_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            kvm_device_present: false,
            bundle_loaded: false,
            service_operations: Vec::new(),
            lifecycle: FaultInjectionEvidence::initial(fault),
            executor_shutdown_succeeded: false,
            process_reaped: false,
            marker_removed: false,
            executor_runtime_clean: false,
            session_root_clean: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(platform: HostPlatform, fault: LifecycleFaultPoint) -> Self {
        let mut report = Self::initial(platform, fault);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("native Linux fault cleanup requires a Linux host".to_string());
        report
    }

    /// Return whether injection and every native cleanup invariant passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.evidence_succeeded()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.platform == HostPlatform::Linux
            && self.bundle_loaded
            && self.service_operations
                == [
                    RuntimeOperation::Features,
                    RuntimeOperation::Create,
                    RuntimeOperation::State,
                    RuntimeOperation::Start,
                    RuntimeOperation::Kill,
                    RuntimeOperation::Delete,
                    RuntimeOperation::Exec,
                    RuntimeOperation::Wait,
                    RuntimeOperation::Pause,
                    RuntimeOperation::Resume,
                    RuntimeOperation::Update,
                    RuntimeOperation::Processes,
                    RuntimeOperation::Stats,
                    RuntimeOperation::SignalProcess,
                    RuntimeOperation::WaitProcess,
                ]
            && self.lifecycle.is_success()
            && self.executor_shutdown_succeeded
            && self.process_reaped
            && self.marker_removed
            && self.executor_runtime_clean
            && self.session_root_clean
            && self.reason.is_none()
    }
}

/// Cleanup evidence after interrupting a utility-VM lifecycle before delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmFaultCleanupReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this cleanup path.
    pub status: CapabilityStatus,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Exact lifecycle prefix and interruption evidence.
    pub lifecycle: FaultInjectionEvidence,
    /// Whether the known workload marker was absent after cleanup.
    pub marker_removed: bool,
    /// Whether VM shutdown left no new guest executor runtime directory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated bridge, VM-exit, and host cleanup evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when cleanup was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmFaultCleanupReport {
    pub(crate) fn initial(platform: HostPlatform, fault: LifecycleFaultPoint) -> Self {
        Self {
            schema_version: OCI_VM_FAULT_CLEANUP_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundle_loaded: false,
            lifecycle: FaultInjectionEvidence::initial(fault),
            marker_removed: false,
            guest_runtime_clean: false,
            bridge: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    pub(crate) fn unsupported(platform: HostPlatform, fault: LifecycleFaultPoint) -> Self {
        let mut report = Self::initial(platform, fault);
        report.status = CapabilityStatus::Unsupported;
        report.bridge.status = CapabilityStatus::Unsupported;
        report.bridge.reason = Some("the authenticated guest bridge was not attempted".to_string());
        report.reason = Some(
            "utility-VM fault cleanup is implemented only for Windows x86_64/WHPX and \
             macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    /// Return whether injection, guest shutdown, and host cleanup all passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.evidence_succeeded()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.platform == self.bridge.platform
            && self.bundle_loaded
            && self.lifecycle.is_success()
            && self.marker_removed
            && self.guest_runtime_clean
            && self.bridge.is_success()
            && self.reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{AgentOperation, AGENT_PROTOCOL_VERSION_MAX};
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::RuntimeOperation;
    use serde_json::json;

    use super::{
        FaultInjectionEvidence, LifecycleFaultPoint, NativeLinuxFaultCleanupReport,
        OciVmFaultCleanupReport,
    };
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    fn complete(point: LifecycleFaultPoint) -> FaultInjectionEvidence {
        FaultInjectionEvidence {
            requested_fault: point,
            injected_fault: Some(point),
            create_completed: true,
            start_completed: point != LifecycleFaultPoint::AfterCreate,
            kill_completed: point == LifecycleFaultPoint::AfterKill,
            created_pid: Some(42),
            marker_absent_after_create: true,
            marker_verified_after_start: point != LifecycleFaultPoint::AfterCreate,
            normal_delete_attempted: false,
        }
    }

    #[test]
    fn each_fault_point_requires_its_exact_completed_prefix_without_delete() {
        for point in [
            LifecycleFaultPoint::AfterCreate,
            LifecycleFaultPoint::AfterStart,
            LifecycleFaultPoint::AfterKill,
        ] {
            assert!(complete(point).is_success(), "{point}");
        }
    }

    #[test]
    fn fault_evidence_rejects_wrong_boundary_extra_operations_and_delete() {
        let baseline = complete(LifecycleFaultPoint::AfterStart);
        for incomplete in [
            FaultInjectionEvidence {
                injected_fault: Some(LifecycleFaultPoint::AfterCreate),
                ..baseline.clone()
            },
            FaultInjectionEvidence {
                kill_completed: true,
                ..baseline.clone()
            },
            FaultInjectionEvidence {
                normal_delete_attempted: true,
                ..baseline.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }
    }

    #[test]
    fn native_report_requires_shutdown_and_every_scoped_resource_cleanup() {
        let mut report = NativeLinuxFaultCleanupReport::initial(
            HostPlatform::Linux,
            LifecycleFaultPoint::AfterStart,
        );
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.service_operations = vec![
            RuntimeOperation::Features,
            RuntimeOperation::Create,
            RuntimeOperation::State,
            RuntimeOperation::Start,
            RuntimeOperation::Kill,
            RuntimeOperation::Delete,
            RuntimeOperation::Exec,
            RuntimeOperation::Wait,
            RuntimeOperation::Pause,
            RuntimeOperation::Resume,
            RuntimeOperation::Update,
            RuntimeOperation::Processes,
            RuntimeOperation::Stats,
            RuntimeOperation::SignalProcess,
            RuntimeOperation::WaitProcess,
        ];
        report.lifecycle = complete(LifecycleFaultPoint::AfterStart);
        report.executor_shutdown_succeeded = true;
        report.process_reaped = true;
        report.marker_removed = true;
        report.executor_runtime_clean = true;
        report.session_root_clean = true;
        assert!(report.is_success());

        report.process_reaped = false;
        assert!(!report.is_success());
    }

    #[test]
    fn vm_report_requires_guest_runtime_and_complete_macos_host_cleanup() {
        let mut report =
            OciVmFaultCleanupReport::initial(HostPlatform::Macos, LifecycleFaultPoint::AfterKill);
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.lifecycle = complete(LifecycleFaultPoint::AfterKill);
        report.marker_removed = true;
        report.guest_runtime_clean = true;
        report.bridge = complete_macos_bridge();
        assert!(report.is_success());

        report.bridge.macos_cleanup = None;
        assert!(!report.is_success());
    }

    fn complete_macos_bridge() -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Macos);
        report.status = CapabilityStatus::Available;
        report.endpoint_bound = true;
        report.endpoint_name = Some("a3s-oci-agent-00000000000000000000000000000000".into());
        report.shim_spawned = true;
        report.shim_process_id = Some(41);
        report.bridge_process_id = Some(42);
        report.shim_client_verified = true;
        report.protocol_negotiated = true;
        report.selected_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.agent_version = Some(env!("CARGO_PKG_VERSION").into());
        report.guest_architecture = Some("aarch64".into());
        report.advertised_operations = vec![
            AgentOperation::Create,
            AgentOperation::State,
            AgentOperation::Start,
            AgentOperation::Kill,
            AgentOperation::Delete,
            AgentOperation::Wait,
            AgentOperation::Exec,
            AgentOperation::SignalProcess,
            AgentOperation::WaitProcess,
            AgentOperation::Pause,
            AgentOperation::Resume,
            AgentOperation::Processes,
            AgentOperation::Update,
            AgentOperation::Stats,
        ];
        report.shim_report_verified = true;
        report.shim_exit_code = Some(0);
        report.console_created = true;
        report.shim_report = Some(json!({}));
        report.macos_cleanup = Some(MacosHostCleanupEvidence {
            endpoint_removed: true,
            shim_reaped: true,
            bridge_reaped: true,
            open_descriptors_before: Some(7),
            open_descriptors_after: Some(7),
            descriptor_inventory_restored: true,
            reason: None,
        });
        report
    }
}
