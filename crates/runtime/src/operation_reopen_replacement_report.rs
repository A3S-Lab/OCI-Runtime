use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerId, ErrorCode, Generation, OperationId};
use serde::{Deserialize, Serialize};

use crate::report::AgentVmSmokeReport;

/// Schema emitted by the real HVF non-Create reopen and owner-replacement diagnostic.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v1";

const QUALIFICATION_FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";

/// Retained evidence for one operation reissued through a replacement HVF owner.
///
/// Version 1 qualifies the context-free `state` operation. Later operations can
/// extend this schema without weakening the exact State recovery invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmOperationReopenReplacementReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this exact recovery path.
    pub status: CapabilityStatus,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Operation interrupted at the selected point in the first VM session.
    pub requested_operation: AgentOperation,
    /// Exact Host or Guest transport point used to force the owner handoff.
    pub requested_stage: AgentTransportOperationStage,
    /// Nonce bound to the armed qualification and retained Guest evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualification_operation_id: Option<OperationId>,
    /// Stable Create identity used to rebuild the pre-start process after reopen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_create_operation_id: Option<OperationId>,
    /// Container identity retained in durable host state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<ContainerId>,
    /// Negotiated protocol version observed at the injected point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated_protocol: Option<u16>,
    /// Exact versioned point reached by the one-shot injector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected_point: Option<String>,
    /// Number of times the selected point was crossed.
    pub fault_crossings: u32,
    /// Stable error class returned by the first operation or disconnect probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_operation_error_code: Option<ErrorCode>,
    /// Operation attached to the first operation or disconnect-probe error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_operation_error_operation: Option<String>,
    /// Whether the first-owner error explicitly allowed the operation to be reissued.
    pub first_operation_error_retryable: bool,
    /// Whether the first owner delivered the selected operation's complete response.
    pub first_operation_response_received: bool,
    /// Whether a follow-up request exposed a post-response disconnect.
    pub disconnect_probe_attempted: bool,
    /// Whether a delivered first response exactly matched the durable record.
    pub first_response_matches_durable_record: bool,
    /// Whether the interrupted operation left the exact durable record in `created`.
    pub durable_created_retained: bool,
    /// Positive init PID retained from the first owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_created_pid: Option<i32>,
    /// Generation retained before the first host service closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_before_reopen: Option<Generation>,
    /// Whether nonce-bound Guest console evidence passed exact validation.
    pub guest_evidence_verified: bool,
    /// Qualification nonce decoded independently from Guest console evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_evidence_operation_id: Option<OperationId>,
    /// Whether a new `HostRuntimeService` opened the same durable root.
    pub host_service_reopened: bool,
    /// Number of durable records accepted by the replacement driver's recovery hook.
    pub replacement_recovery_calls: u32,
    /// Whether recovery rebuilt the first owner's pre-start process in the fresh Guest.
    pub replacement_rehydrated_created_record: bool,
    /// Whether the selected operation completed through the replacement owner.
    pub operation_completed_after_reopen: bool,
    /// Generation returned by the replacement operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_after_reopen: Option<Generation>,
    /// Positive init PID observed through the replacement Guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_created_pid: Option<i32>,
    /// Whether the replacement response exactly matched the recovered durable record.
    pub replacement_response_matches_durable_record: bool,
    /// Whether the exact durable generation was observed across the owner handoff.
    pub same_generation_reused: bool,
    /// Whether replacement recovery reused the original setup Create identity.
    pub setup_create_identity_reused: bool,
    /// Whether force delete completed through the replacement VM owner.
    pub force_delete_completed: bool,
    /// Whether no durable container record remained after delete.
    pub durable_records_empty: bool,
    /// Whether the workload marker remained absent after complete cleanup.
    pub marker_absent_after_cleanup: bool,
    /// Whether the first guest executor returned to its original runtime inventory.
    pub first_guest_runtime_clean: bool,
    /// Whether the replacement guest executor returned to the same inventory.
    pub replacement_guest_runtime_clean: bool,
    /// Whether endpoint, shim, and VM-worker identities prove two different owners.
    pub owners_distinct: bool,
    /// Whether the command removed its newly created qualification state root.
    pub state_root_removed: bool,
    /// First authenticated VM and host cleanup evidence.
    pub first_vm: AgentVmSmokeReport,
    /// Replacement authenticated VM and host cleanup evidence.
    pub replacement_vm: AgentVmSmokeReport,
    /// Diagnostic reason when the evidence was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmOperationReopenReplacementReport {
    pub(crate) fn initial_state(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        Self {
            schema_version: OCI_VM_OPERATION_REOPEN_REPLACEMENT_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundle_loaded: false,
            requested_operation: AgentOperation::State,
            requested_stage,
            qualification_operation_id: None,
            setup_create_operation_id: None,
            container_id: None,
            negotiated_protocol: None,
            injected_point: None,
            fault_crossings: 0,
            first_operation_error_code: None,
            first_operation_error_operation: None,
            first_operation_error_retryable: false,
            first_operation_response_received: false,
            disconnect_probe_attempted: false,
            first_response_matches_durable_record: false,
            durable_created_retained: false,
            first_created_pid: None,
            generation_before_reopen: None,
            guest_evidence_verified: false,
            guest_evidence_operation_id: None,
            host_service_reopened: false,
            replacement_recovery_calls: 0,
            replacement_rehydrated_created_record: false,
            operation_completed_after_reopen: false,
            generation_after_reopen: None,
            replacement_created_pid: None,
            replacement_response_matches_durable_record: false,
            same_generation_reused: false,
            setup_create_identity_reused: false,
            force_delete_completed: false,
            durable_records_empty: false,
            marker_absent_after_cleanup: false,
            first_guest_runtime_clean: false,
            replacement_guest_runtime_clean: false,
            owners_distinct: false,
            state_root_removed: false,
            first_vm: AgentVmSmokeReport::initial(platform),
            replacement_vm: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported_state(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_state(platform, requested_stage);
        report.status = CapabilityStatus::Unsupported;
        report.first_vm.status = CapabilityStatus::Unsupported;
        report.first_vm.reason = Some("the first HVF owner was not started".to_string());
        report.replacement_vm.status = CapabilityStatus::Unsupported;
        report.replacement_vm.reason =
            Some("the replacement HVF owner was not started".to_string());
        report.reason = Some(
            "real utility-VM operation reopen and owner replacement is implemented only for macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    /// Return whether the exact operation handoff and both VM cleanup gates passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.evidence_succeeded()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        let expected_point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: self.requested_operation,
            stage: self.requested_stage,
        }
        .to_string();
        let guest_stage = self.requested_stage.is_guest();
        let response_delivered = matches!(
            self.requested_stage,
            AgentTransportOperationStage::GuestAfterResponseWrite
        );
        let expected_error_operation = if guest_stage {
            self.first_operation_error_operation
                .as_deref()
                .is_some_and(crate::transport_cleanup_report::is_retryable_disconnect_operation)
        } else {
            self.first_operation_error_operation.as_deref() == Some(QUALIFICATION_FAULT_OPERATION)
        };
        let expected_guest_evidence = if guest_stage {
            self.guest_evidence_verified
                && self.guest_evidence_operation_id == self.qualification_operation_id
        } else {
            !self.guest_evidence_verified && self.guest_evidence_operation_id.is_none()
        };

        matches!(self.platform, HostPlatform::Macos)
            && self.first_vm.platform == self.platform
            && self.replacement_vm.platform == self.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::State
            && (self.requested_stage.is_host() || guest_stage)
            && self.qualification_operation_id.is_some()
            && self.setup_create_operation_id.is_some()
            && self.qualification_operation_id != self.setup_create_operation_id
            && self.container_id.is_some()
            && self.negotiated_protocol == Some(AGENT_PROTOCOL_VERSION_MAX)
            && self.injected_point.as_deref() == Some(expected_point.as_str())
            && self.fault_crossings == 1
            && self.first_operation_error_code == Some(ErrorCode::Unavailable)
            && expected_error_operation
            && self.first_operation_error_retryable
            && self.first_operation_response_received == response_delivered
            && self.disconnect_probe_attempted == response_delivered
            && self.first_response_matches_durable_record == response_delivered
            && self.durable_created_retained
            && self.first_created_pid.is_some_and(|pid| pid > 0)
            && self.generation_before_reopen.is_some()
            && expected_guest_evidence
            && self.host_service_reopened
            && self.replacement_recovery_calls == 1
            && self.replacement_rehydrated_created_record
            && self.operation_completed_after_reopen
            && self.generation_before_reopen == self.generation_after_reopen
            && self.replacement_created_pid.is_some_and(|pid| pid > 0)
            && self.replacement_response_matches_durable_record
            && self.same_generation_reused
            && self.setup_create_identity_reused
            && self.force_delete_completed
            && self.durable_records_empty
            && self.marker_absent_after_cleanup
            && self.first_guest_runtime_clean
            && self.replacement_guest_runtime_clean
            && self.owners_distinct
            && self.owner_identities_are_distinct()
            && self.state_root_removed
            && self.first_vm.is_success()
            && self.replacement_vm.is_success()
            && self.reason.is_none()
    }

    fn owner_identities_are_distinct(&self) -> bool {
        self.first_vm
            .endpoint_name
            .as_deref()
            .zip(self.replacement_vm.endpoint_name.as_deref())
            .is_some_and(|(first, replacement)| !first.is_empty() && first != replacement)
            && self
                .first_vm
                .shim_process_id
                .zip(self.replacement_vm.shim_process_id)
                .is_some_and(|(first, replacement)| first != 0 && first != replacement)
            && self
                .first_vm
                .bridge_process_id
                .zip(self.replacement_vm.bridge_process_id)
                .is_some_and(|(first, replacement)| first != 0 && first != replacement)
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ContainerId, ErrorCode, Generation, OperationId};
    use serde_json::json;

    use super::OciVmOperationReopenReplacementReport;
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn state_report_requires_all_nine_exact_handoffs_and_complete_cleanup() {
        let mut report = OciVmOperationReopenReplacementReport::initial_state(
            HostPlatform::Macos,
            AgentTransportOperationStage::HostBeforeRequestWrite,
        );
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("reopen-state").expect("qualification ID"));
        report.setup_create_operation_id =
            Some(OperationId::new("reopen-state-create").expect("Create ID"));
        report.container_id = Some(ContainerId::new("reopen-state").expect("container ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.state-host-before-request-write"
        ));
        report.fault_crossings = 1;
        report.first_operation_error_code = Some(ErrorCode::Unavailable);
        report.first_operation_error_operation =
            Some("oci-vm-transport-qualification-fault".to_string());
        report.first_operation_error_retryable = true;
        report.durable_created_retained = true;
        report.first_created_pid = Some(41);
        report.generation_before_reopen = Some(Generation(1));
        report.host_service_reopened = true;
        report.replacement_recovery_calls = 1;
        report.replacement_rehydrated_created_record = true;
        report.operation_completed_after_reopen = true;
        report.generation_after_reopen = Some(Generation(1));
        report.replacement_created_pid = Some(42);
        report.replacement_response_matches_durable_record = true;
        report.same_generation_reused = true;
        report.setup_create_identity_reused = true;
        report.force_delete_completed = true;
        report.durable_records_empty = true;
        report.marker_absent_after_cleanup = true;
        report.first_guest_runtime_clean = true;
        report.replacement_guest_runtime_clean = true;
        report.owners_distinct = true;
        report.state_root_removed = true;
        report.first_vm = complete_macos_bridge("first", 11, 12);
        report.replacement_vm = complete_macos_bridge("replacement", 21, 22);
        assert!(report.is_success());

        for stage in AgentTransportOperationStage::ALL {
            let mut stage_report = report.clone();
            stage_report.requested_stage = stage;
            stage_report.injected_point = Some(format!(
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.state-{}",
                stage.as_str()
            ));
            if stage.is_guest() {
                stage_report.first_operation_error_operation =
                    Some("read-agent-frame-header".to_string());
                stage_report.guest_evidence_verified = true;
                stage_report.guest_evidence_operation_id =
                    stage_report.qualification_operation_id.clone();
            }
            if stage == AgentTransportOperationStage::GuestAfterResponseWrite {
                stage_report.first_operation_response_received = true;
                stage_report.disconnect_probe_attempted = true;
                stage_report.first_response_matches_durable_record = true;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        for incomplete in [
            OciVmOperationReopenReplacementReport {
                replacement_rehydrated_created_record: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                replacement_response_matches_durable_record: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                setup_create_identity_reused: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                force_delete_completed: false,
                ..report.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }

        report.replacement_vm.endpoint_name = report.first_vm.endpoint_name.clone();
        assert!(!report.is_success());
    }

    fn complete_macos_bridge(name: &str, shim: u32, bridge: u32) -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Macos);
        report.status = CapabilityStatus::Available;
        report.endpoint_bound = true;
        report.endpoint_name = Some(format!("a3s-oci-agent-{name}"));
        report.shim_spawned = true;
        report.shim_process_id = Some(shim);
        report.bridge_process_id = Some(bridge);
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
}
