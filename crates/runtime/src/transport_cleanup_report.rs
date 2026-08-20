use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportShutdownStage, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ErrorCode, OperationId};
use serde::{Deserialize, Serialize};

use crate::report::AgentVmSmokeReport;

/// Schema emitted by the real utility-VM Host/Guest transport cleanup diagnostic.
pub const OCI_VM_TRANSPORT_FAULT_CLEANUP_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-transport-fault-cleanup.v3";

/// Retained evidence for one real utility-VM transport interruption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmTransportFaultCleanupReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this exact fault-cleanup path.
    pub status: CapabilityStatus,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Operation selected for real transport interruption.
    pub requested_operation: AgentOperation,
    /// Nonce-bearing idempotency identity selected for this qualification run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualification_operation_id: Option<OperationId>,
    /// Host/Guest request-response or Host shutdown transition selected for interruption.
    pub requested_stage: AgentTransportFaultStage,
    /// Negotiated protocol version observed at the selected transition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated_protocol: Option<u16>,
    /// Exact versioned point reached by the one-shot injector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected_point: Option<String>,
    /// Number of times the selected point was crossed.
    pub fault_crossings: u32,
    /// Stable error class returned by the interrupted operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_error_code: Option<ErrorCode>,
    /// Operation attached to the interrupted call's error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_error_operation: Option<String>,
    /// Whether the interrupted call was explicitly retryable.
    pub observed_error_retryable: bool,
    /// Whether the primary Create response was fully observed by the host.
    pub primary_response_received: bool,
    /// Whether a follow-up request proved disconnect after a delivered response.
    pub disconnect_probe_attempted: bool,
    /// Whether nonce-bound Guest console evidence passed exact validation.
    pub guest_evidence_verified: bool,
    /// Operation identity decoded independently from Guest console evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_evidence_operation_id: Option<OperationId>,
    /// Whether the diagnostic attempted normal OCI delete after interruption.
    pub normal_delete_attempted: bool,
    /// Whether the configured workload marker remained absent after cleanup.
    pub marker_absent_after_cleanup: bool,
    /// Whether VM shutdown left no new guest executor runtime directory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated bridge, VM-exit, and host cleanup evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when the evidence was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmTransportFaultCleanupReport {
    pub(crate) fn initial(platform: HostPlatform, stage: AgentTransportFaultStage) -> Self {
        Self {
            schema_version: OCI_VM_TRANSPORT_FAULT_CLEANUP_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundle_loaded: false,
            requested_operation: AgentOperation::Create,
            qualification_operation_id: None,
            requested_stage: stage,
            negotiated_protocol: None,
            injected_point: None,
            fault_crossings: 0,
            observed_error_code: None,
            observed_error_operation: None,
            observed_error_retryable: false,
            primary_response_received: false,
            disconnect_probe_attempted: false,
            guest_evidence_verified: false,
            guest_evidence_operation_id: None,
            normal_delete_attempted: false,
            marker_absent_after_cleanup: false,
            guest_runtime_clean: false,
            bridge: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    pub(crate) fn unsupported(platform: HostPlatform, stage: AgentTransportFaultStage) -> Self {
        let mut report = Self::initial(platform, stage);
        report.status = CapabilityStatus::Unsupported;
        report.bridge.status = CapabilityStatus::Unsupported;
        report.bridge.reason = Some("the authenticated guest bridge was not attempted".to_string());
        report.reason = Some(
            "real utility-VM transport fault cleanup is implemented only for Linux \
             x86_64/aarch64 KVM, Windows x86_64/WHPX, and macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    /// Return whether the exact interruption and every cleanup invariant passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.evidence_succeeded()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        let expected_point = match self.requested_stage {
            AgentTransportFaultStage::Operation(stage) => AgentTransportFaultPoint::Operation {
                protocol_version: AGENT_PROTOCOL_VERSION_MAX,
                operation: AgentOperation::Create,
                stage,
            },
            AgentTransportFaultStage::Shutdown(stage) => AgentTransportFaultPoint::Shutdown {
                protocol_version: AGENT_PROTOCOL_VERSION_MAX,
                stage,
            },
        }
        .to_string();
        let common = matches!(
            self.platform,
            HostPlatform::Linux | HostPlatform::Macos | HostPlatform::Windows
        ) && self.platform == self.bridge.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::Create
            && self.qualification_operation_id.is_some()
            && is_supported_transport_fault_stage(self.requested_stage)
            && self.negotiated_protocol == Some(AGENT_PROTOCOL_VERSION_MAX)
            && self.injected_point.as_deref() == Some(expected_point.as_str())
            && self.fault_crossings == 1
            && self.observed_error_code == Some(ErrorCode::Unavailable)
            && self.observed_error_retryable
            && !self.normal_delete_attempted
            && self.marker_absent_after_cleanup
            && self.guest_runtime_clean
            && self.bridge.is_success()
            && self.reason.is_none();
        if !common {
            return false;
        }

        match self.requested_stage {
            AgentTransportFaultStage::Operation(stage) if is_supported_host_stage(stage) => {
                self.observed_error_operation.as_deref()
                    == Some("oci-vm-transport-qualification-fault")
                    && !self.primary_response_received
                    && !self.disconnect_probe_attempted
                    && !self.guest_evidence_verified
                    && self.guest_evidence_operation_id.is_none()
            }
            AgentTransportFaultStage::Operation(stage) => {
                self.observed_error_operation
                    .as_deref()
                    .is_some_and(is_retryable_disconnect_operation)
                    && self.guest_evidence_verified
                    && self.guest_evidence_operation_id == self.qualification_operation_id
                    && self.primary_response_received
                        == matches!(stage, AgentTransportOperationStage::GuestAfterResponseWrite)
                    && self.disconnect_probe_attempted == self.primary_response_received
            }
            AgentTransportFaultStage::Shutdown(stage) => {
                is_supported_shutdown_stage(stage)
                    && self.observed_error_operation.as_deref()
                        == Some("oci-vm-transport-qualification-fault")
                    && self.primary_response_received
                    && !self.disconnect_probe_attempted
                    && !self.guest_evidence_verified
                    && self.guest_evidence_operation_id.is_none()
            }
        }
    }
}

/// Whether the first real-host diagnostic implements this exact transition.
#[must_use]
pub const fn is_supported_host_stage(stage: AgentTransportOperationStage) -> bool {
    stage.is_host()
}

/// Whether the real-host diagnostic implements this Guest transition.
#[must_use]
pub const fn is_supported_guest_stage(stage: AgentTransportOperationStage) -> bool {
    stage.is_guest()
}

/// Whether the real-host diagnostic implements this shutdown transition.
#[must_use]
pub const fn is_supported_shutdown_stage(stage: AgentTransportShutdownStage) -> bool {
    matches!(
        stage,
        AgentTransportShutdownStage::HostBeforeShutdown
            | AgentTransportShutdownStage::HostAfterShutdown
    )
}

/// Whether the real-host diagnostic implements this operation transition.
#[must_use]
pub const fn is_supported_transport_stage(stage: AgentTransportOperationStage) -> bool {
    stage.is_host() || stage.is_guest()
}

/// Whether the real-host diagnostic implements this operation or shutdown transition.
#[must_use]
pub const fn is_supported_transport_fault_stage(stage: AgentTransportFaultStage) -> bool {
    match stage {
        AgentTransportFaultStage::Operation(stage) => is_supported_transport_stage(stage),
        AgentTransportFaultStage::Shutdown(stage) => is_supported_shutdown_stage(stage),
    }
}

pub(crate) fn is_retryable_disconnect_operation(operation: &str) -> bool {
    matches!(
        operation,
        "agent-protocol"
            | "read-agent-frame-header"
            | "read-agent-frame-payload"
            | "write-agent-frame-header"
            | "write-agent-frame-payload"
            | "flush-agent-frame"
    )
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
        AgentTransportShutdownStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ErrorCode, OperationId};
    use serde_json::json;

    use super::OciVmTransportFaultCleanupReport;
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn transport_report_requires_the_exact_fault_and_complete_vm_cleanup() {
        let stage = AgentTransportOperationStage::HostAfterRequestWrite;
        let mut report =
            OciVmTransportFaultCleanupReport::initial(HostPlatform::Macos, stage.into());
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("transport-report-create").expect("operation ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.create-{}",
            stage.as_str()
        ));
        report.fault_crossings = 1;
        report.observed_error_code = Some(ErrorCode::Unavailable);
        report.observed_error_operation = Some("oci-vm-transport-qualification-fault".to_string());
        report.observed_error_retryable = true;
        report.marker_absent_after_cleanup = true;
        report.guest_runtime_clean = true;
        report.bridge = complete_macos_bridge();
        assert!(report.is_success());

        for incomplete in [
            OciVmTransportFaultCleanupReport {
                fault_crossings: 2,
                ..report.clone()
            },
            OciVmTransportFaultCleanupReport {
                observed_error_retryable: false,
                ..report.clone()
            },
            OciVmTransportFaultCleanupReport {
                normal_delete_attempted: true,
                ..report.clone()
            },
            OciVmTransportFaultCleanupReport {
                marker_absent_after_cleanup: false,
                ..report.clone()
            },
            OciVmTransportFaultCleanupReport {
                injected_point: Some("agent-v9.create-wrong-stage".to_string()),
                ..report.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }

        report.bridge.macos_cleanup = None;
        assert!(!report.is_success());
    }

    #[test]
    fn transport_report_accepts_complete_linux_kvm_cleanup_evidence() {
        let stage = AgentTransportOperationStage::HostAfterRequestWrite;
        let mut report =
            OciVmTransportFaultCleanupReport::initial(HostPlatform::Linux, stage.into());
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("linux-transport-report-create").expect("operation ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.create-{}",
            stage.as_str()
        ));
        report.fault_crossings = 1;
        report.observed_error_code = Some(ErrorCode::Unavailable);
        report.observed_error_operation = Some("oci-vm-transport-qualification-fault".to_string());
        report.observed_error_retryable = true;
        report.marker_absent_after_cleanup = true;
        report.guest_runtime_clean = true;
        report.bridge = complete_linux_bridge();

        assert!(report.is_success());

        report.bridge.shim_report = None;
        assert!(!report.is_success());
    }

    #[test]
    fn transport_report_requires_nonce_bound_evidence_for_guest_stages() {
        let stage = AgentTransportOperationStage::GuestAfterDispatch;
        let mut report =
            OciVmTransportFaultCleanupReport::initial(HostPlatform::Macos, stage.into());
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("guest-transport-report-create").expect("operation ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.create-{}",
            stage.as_str()
        ));
        report.fault_crossings = 1;
        report.observed_error_code = Some(ErrorCode::Unavailable);
        report.observed_error_operation = Some("agent-protocol".to_string());
        report.observed_error_retryable = true;
        report.marker_absent_after_cleanup = true;
        report.guest_runtime_clean = true;
        report.bridge = complete_macos_bridge();
        assert!(!report.is_success());
        report.guest_evidence_verified = true;
        report.guest_evidence_operation_id = report.qualification_operation_id.clone();
        assert!(report.is_success());

        report.primary_response_received = true;
        assert!(!report.is_success());
    }

    #[test]
    fn transport_report_requires_a_successful_create_before_shutdown_fault() {
        let stage = AgentTransportShutdownStage::HostBeforeShutdown;
        let mut report =
            OciVmTransportFaultCleanupReport::initial(HostPlatform::Macos, stage.into());
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("shutdown-transport-report-create").expect("operation ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(
            AgentTransportFaultPoint::Shutdown {
                protocol_version: AGENT_PROTOCOL_VERSION_MAX,
                stage,
            }
            .to_string(),
        );
        report.fault_crossings = 1;
        report.observed_error_code = Some(ErrorCode::Unavailable);
        report.observed_error_operation = Some("oci-vm-transport-qualification-fault".to_string());
        report.observed_error_retryable = true;
        report.primary_response_received = true;
        report.marker_absent_after_cleanup = true;
        report.guest_runtime_clean = true;
        report.bridge = complete_macos_bridge();
        assert!(report.is_success());

        report.primary_response_received = false;
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
        report.advertised_operations = AgentOperation::ALL.to_vec();
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

    fn complete_linux_bridge() -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Linux);
        report.status = CapabilityStatus::Available;
        report.endpoint_bound = true;
        report.endpoint_name = Some("a3s-oci-agent-linux-transport".into());
        report.shim_spawned = true;
        report.shim_process_id = Some(101);
        report.bridge_process_id = Some(102);
        report.shim_client_verified = true;
        report.protocol_negotiated = true;
        report.selected_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.agent_version = Some(env!("CARGO_PKG_VERSION").into());
        report.guest_architecture = Some(std::env::consts::ARCH.into());
        report.advertised_operations = AgentOperation::ALL.to_vec();
        report.shim_report_verified = true;
        report.shim_exit_code = Some(0);
        report.console_created = true;
        report.shim_report = Some(json!({"status": "available"}));
        report
    }
}
