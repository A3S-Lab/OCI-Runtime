use a3s_oci_agent_protocol::{AgentOperation, AGENT_PROTOCOL_VERSION_MAX};
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::RuntimeOperation;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema emitted by the WHPX smoke command.
pub const WHPX_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.whpx-smoke.v1";
/// Schema emitted by the authenticated guest-agent VM smoke.
pub const AGENT_VM_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.agent-vm-smoke.v1";
/// Schema emitted by the fixed OCI core-lifecycle utility-VM smoke.
pub const OCI_VM_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.oci-vm-smoke.v2";
/// Schema emitted by the native Linux SDK lifecycle smoke.
pub const NATIVE_LINUX_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.native-linux-smoke.v1";

/// Result of querying WHPX and creating then deleting a partition object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host status of the Windows Hypervisor Platform prerequisite.
    pub status: CapabilityStatus,
    /// Whether `WinHvPlatform.dll` loaded from the system search scope.
    pub dll_loaded: bool,
    /// Whether WHPX reported the Windows hypervisor present.
    pub hypervisor_present: bool,
    /// Whether a partition object was created and deleted successfully.
    pub partition_object_round_trip: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WhpxSmokeReport {
    #[cfg(windows)]
    pub(crate) fn unavailable(
        dll_loaded: bool,
        hypervisor_present: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            dll_loaded,
            hypervisor_present,
            partition_object_round_trip: false,
            reason: Some(reason.into()),
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unsupported,
            dll_loaded: false,
            hypervisor_present: false,
            partition_object_round_trip: false,
            reason: Some(reason.into()),
        }
    }

    #[cfg(windows)]
    pub(crate) fn success() -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Available,
            dll_loaded: true,
            hypervisor_present: true,
            partition_object_round_trip: true,
            reason: None,
        }
    }

    /// Return whether every smoke step succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.dll_loaded
            && self.hypervisor_present
            && self.partition_object_round_trip
    }
}

/// End-to-end evidence from host pipe binding through guest-agent negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentVmSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the diagnostic path.
    pub status: CapabilityStatus,
    /// Whether an exclusive, protected host endpoint was bound.
    pub endpoint_bound: bool,
    /// Whether the isolated libkrun shim process was started.
    pub shim_spawned: bool,
    /// Process ID used for named-pipe peer authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim_process_id: Option<u32>,
    /// Whether the connected pipe client matched the exact shim PID.
    pub shim_client_verified: bool,
    /// Whether token authentication and protocol negotiation succeeded.
    pub protocol_negotiated: bool,
    /// Selected guest-agent protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_protocol: Option<u16>,
    /// Version reported by the agent started at the fixed guest path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// Guest architecture reported during negotiation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_architecture: Option<String>,
    /// Exact operations advertised by the guest.
    pub advertised_operations: Vec<AgentOperation>,
    /// Whether the shim's bounded machine-readable evidence was valid.
    pub shim_report_verified: bool,
    /// Exit code returned by the isolated shim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim_exit_code: Option<i32>,
    /// Whether libkrun created the requested guest console file.
    pub console_created: bool,
    /// Exact shim evidence retained without linking libkrun into the runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim_report: Option<Value>,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AgentVmSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: AGENT_VM_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            endpoint_bound: false,
            shim_spawned: false,
            shim_process_id: None,
            shim_client_verified: false,
            protocol_negotiated: false,
            selected_protocol: None,
            agent_version: None,
            guest_architecture: None,
            advertised_operations: Vec::new(),
            shim_report_verified: false,
            shim_exit_code: None,
            console_created: false,
            shim_report: None,
            reason: None,
        }
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some(
            "the authenticated guest-agent VM smoke is implemented only for Windows x86_64/WHPX"
                .into(),
        );
        report
    }

    /// Return whether host authentication, guest negotiation, and VM exit succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.endpoint_bound
            && self.shim_spawned
            && self
                .shim_process_id
                .is_some_and(|process_id| process_id != 0)
            && self.shim_client_verified
            && self.protocol_negotiated
            && self.selected_protocol == Some(AGENT_PROTOCOL_VERSION_MAX)
            && self.agent_version.as_deref() == Some(env!("CARGO_PKG_VERSION"))
            && self.guest_architecture.as_deref() == Some("x86_64")
            && self.advertised_operations
                == [
                    AgentOperation::Create,
                    AgentOperation::State,
                    AgentOperation::Start,
                    AgentOperation::Kill,
                    AgentOperation::Delete,
                ]
            && self.shim_report_verified
            && self.shim_exit_code == Some(0)
            && self.console_created
            && self.shim_report.is_some()
    }
}

/// End-to-end SDK evidence for the native Linux executor path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the native lifecycle path.
    pub status: CapabilityStatus,
    /// Whether `/dev/kvm` existed while the independent native path ran.
    pub kvm_device_present: bool,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Operations advertised by the explicitly opened native service.
    pub service_operations: Vec<RuntimeOperation>,
    /// Whether dedicated-VM isolation failed before claiming the create ID.
    pub dedicated_vm_rejected_before_create: bool,
    /// Whether create returned the exact OCI `created` barrier.
    pub create_returned_created: bool,
    /// Whether retrying create replayed its exact original result.
    pub create_replayed: bool,
    /// Host-visible init PID returned while the container was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether the workload marker remained absent before start.
    pub marker_absent_after_create: bool,
    /// Whether start released the prepared init wrapper.
    pub start_released: bool,
    /// Whether the configured process was observed running.
    pub running_observed: bool,
    /// Whether the driver accepted the exact signal request.
    pub kill_delivered: bool,
    /// Whether retrying kill replayed its exact original result.
    pub kill_replayed: bool,
    /// Whether state eventually reported the workload stopped.
    pub stopped_observed: bool,
    /// Whether the workload produced the exact expected marker.
    pub marker_verified: bool,
    /// Whether stopped-only delete succeeded.
    pub delete_succeeded: bool,
    /// Whether retrying delete replayed its exact success.
    pub delete_replayed: bool,
    /// Whether state returned `not-found` after delete.
    pub state_missing_after_delete: bool,
    /// Whether the host removed the known marker.
    pub marker_removed: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the smoke removed its isolated durable and transient workspace.
    pub session_root_clean: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: NATIVE_LINUX_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            kvm_device_present: false,
            bundle_loaded: false,
            service_operations: Vec::new(),
            dedicated_vm_rejected_before_create: false,
            create_returned_created: false,
            create_replayed: false,
            created_pid: None,
            marker_absent_after_create: false,
            start_released: false,
            running_observed: false,
            kill_delivered: false,
            kill_replayed: false,
            stopped_observed: false,
            marker_verified: false,
            delete_succeeded: false,
            delete_replayed: false,
            state_missing_after_delete: false,
            marker_removed: false,
            executor_runtime_clean: false,
            session_root_clean: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("the native OCI lifecycle smoke requires a Linux host".into());
        report
    }

    /// Return whether the complete native lifecycle and cleanup passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.lifecycle_succeeded()
    }

    pub(crate) fn lifecycle_succeeded(&self) -> bool {
        self.bundle_loaded
            && self.service_operations
                == [
                    RuntimeOperation::Features,
                    RuntimeOperation::Create,
                    RuntimeOperation::State,
                    RuntimeOperation::Start,
                    RuntimeOperation::Kill,
                    RuntimeOperation::Delete,
                ]
            && self.dedicated_vm_rejected_before_create
            && self.create_returned_created
            && self.create_replayed
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.marker_absent_after_create
            && self.start_released
            && self.running_observed
            && self.kill_delivered
            && self.kill_replayed
            && self.stopped_observed
            && self.marker_verified
            && self.delete_succeeded
            && self.delete_replayed
            && self.state_missing_after_delete
            && self.marker_removed
            && self.executor_runtime_clean
            && self.session_root_clean
    }
}

/// End-to-end evidence for the fixed OCI core lifecycle in a real utility VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this diagnostic path.
    pub status: CapabilityStatus,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Whether create returned the exact OCI `created` barrier.
    pub create_returned_created: bool,
    /// Whether retrying create replayed its exact original result.
    pub create_replayed: bool,
    /// Guest init-wrapper PID returned while the container was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether the workload marker remained absent before start.
    pub marker_absent_after_create: bool,
    /// Whether start released the prepared init wrapper.
    pub start_released: bool,
    /// Whether the configured process was observed running.
    pub running_observed: bool,
    /// Whether the guest accepted the exact signal request.
    pub kill_delivered: bool,
    /// Whether retrying kill replayed its exact original result.
    pub kill_replayed: bool,
    /// Whether state eventually reported the workload stopped.
    pub stopped_observed: bool,
    /// Whether the workload produced the exact expected marker.
    pub marker_verified: bool,
    /// Whether stopped-only delete succeeded.
    pub delete_succeeded: bool,
    /// Whether retrying delete replayed its exact success.
    pub delete_replayed: bool,
    /// Whether state returned `not-found` after delete.
    pub state_missing_after_delete: bool,
    /// Whether the host removed the known marker.
    pub marker_removed: bool,
    /// Whether VM shutdown left no new guest-agent runtime directory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated host/guest and shim evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: OCI_VM_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundle_loaded: false,
            create_returned_created: false,
            create_replayed: false,
            created_pid: None,
            marker_absent_after_create: false,
            start_released: false,
            running_observed: false,
            kill_delivered: false,
            kill_replayed: false,
            stopped_observed: false,
            marker_verified: false,
            delete_succeeded: false,
            delete_replayed: false,
            state_missing_after_delete: false,
            marker_removed: false,
            guest_runtime_clean: false,
            bridge: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.bridge = AgentVmSmokeReport::unsupported(platform);
        report.reason =
            Some("the fixed OCI VM smoke is implemented only for Windows x86_64/WHPX".into());
        report
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.bundle_loaded
            && self.create_returned_created
            && self.create_replayed
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.marker_absent_after_create
            && self.start_released
            && self.running_observed
            && self.kill_delivered
            && self.kill_replayed
            && self.stopped_observed
            && self.marker_verified
            && self.delete_succeeded
            && self.delete_replayed
            && self.state_missing_after_delete
            && self.marker_removed
            && self.guest_runtime_clean
            && self.bridge.is_success()
    }
}
