use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;

use super::{
    OciVmOperationReopenReplacementReport,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_CLOSE_STDIN_SCHEMA_VERSION, QUALIFICATION_FAULT_OPERATION,
};

impl OciVmOperationReopenReplacementReport {
    pub(crate) fn initial_close_stdin(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_state(platform, requested_stage);
        report.schema_version =
            OCI_VM_OPERATION_REOPEN_REPLACEMENT_CLOSE_STDIN_SCHEMA_VERSION.to_string();
        report.requested_operation = AgentOperation::CloseStdin;
        report.exec_terminal = Some(false);
        report
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported_close_stdin(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_close_stdin(platform, requested_stage);
        report.status = CapabilityStatus::Unsupported;
        report.first_vm.status = CapabilityStatus::Unsupported;
        report.first_vm.reason = Some("the first HVF owner was not started".to_string());
        report.replacement_vm.status = CapabilityStatus::Unsupported;
        report.replacement_vm.reason =
            Some("the replacement HVF owner was not started".to_string());
        report.reason = Some(
            "real utility-VM CloseStdin reopen and owner replacement is implemented only for macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    pub(super) fn close_stdin_evidence_succeeded(&self) -> bool {
        let expected_point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::CloseStdin,
            stage: self.requested_stage,
        }
        .to_string();
        let guest_stage = self.requested_stage.is_guest();
        let response_delivered =
            self.requested_stage == AgentTransportOperationStage::GuestAfterResponseWrite;
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
        let setup_ids_are_distinct = self
            .qualification_operation_id
            .as_ref()
            .zip(self.setup_create_operation_id.as_ref())
            .zip(self.setup_start_operation_id.as_ref())
            .zip(self.setup_exec_operation_id.as_ref())
            .is_some_and(|(((close, create), start), exec)| {
                close != create
                    && close != start
                    && close != exec
                    && create != start
                    && create != exec
                    && start != exec
            });

        matches!(self.platform, HostPlatform::Macos)
            && self.first_vm.platform == self.platform
            && self.replacement_vm.platform == self.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::CloseStdin
            && self.kill_signal.is_none()
            && self.kill_all.is_none()
            && self.delete_mode.is_none()
            && self.wait_timeout_ms.is_none()
            && self.expected_exit_status.is_none()
            && self.first_wait_exit_status.is_none()
            && self.replacement_wait_exit_status.is_none()
            && self.cached_wait_exit_status.is_none()
            && self
                .exec_process_id
                .as_ref()
                .is_some_and(|process_id| !process_id.is_init())
            && self.exec_terminal == Some(false)
            && self.signal_process_signal.is_none()
            && self.write_stdin_data.is_none()
            && (self.requested_stage.is_host() || guest_stage)
            && setup_ids_are_distinct
            && self.setup_kill_operation_id.is_none()
            && self.container_id.is_some()
            && self.negotiated_protocol == Some(AGENT_PROTOCOL_VERSION_MAX)
            && self.injected_point.as_deref() == Some(expected_point.as_str())
            && self.fault_crossings == 1
            && self.first_operation_error_code == Some(a3s_oci_sdk::ErrorCode::Unavailable)
            && expected_error_operation
            && self.first_operation_error_retryable
            && !self.first_operation_response_received
            && !self.disconnect_probe_attempted
            && self.first_response_matches_durable_record == response_delivered
            && !self.first_response_matches_expected_exit
            && !self.durable_created_retained
            && self.durable_running_retained
            && !self.durable_stopped_retained
            && !self.first_durable_records_empty
            && !self.delete_journal_prepared_before_reopen
            && !self.delete_journal_succeeded_empty_before_reopen
            && !self.init_exit_cached_before_reopen
            && !self.exec_journal_prepared_before_reopen
            && self.exec_journal_succeeded_before_reopen
            && self.close_stdin_journal_prepared_before_reopen != response_delivered
            && self.close_stdin_journal_succeeded_before_reopen == response_delivered
            && self.first_created_pid.is_some_and(|pid| pid > 0)
            && self.first_exec_pid.is_some_and(|pid| pid > 0)
            && self.generation_before_reopen.is_some()
            && expected_guest_evidence
            && self.host_service_reopened
            && self.replacement_recovery_calls == 1
            && self.replacement_rehydrated_created_record
            && self.replacement_rehydrated_running_record
            && !self.replacement_rehydrated_stopped_record
            && self.replacement_rehydrated_exec_record
            && self.replacement_rehydrated_close_stdin == response_delivered
            && self.operation_completed_after_reopen
            && self.generation_before_reopen == self.generation_after_reopen
            && self.replacement_created_pid.is_some_and(|pid| pid > 0)
            && self.replacement_exec_pid.is_some_and(|pid| pid > 0)
            && self.replacement_response_matches_durable_record
            && !self.replacement_response_matches_expected_exit
            && !self.cached_response_matches_expected_exit
            && !self.init_exit_cached_after_reopen
            && self.same_generation_reused
            && self.setup_create_identity_reused
            && self.setup_start_identity_reused
            && !self.setup_kill_identity_reused
            && self.same_operation_id_reused
            && self.setup_create_response_rebound
            && self.setup_start_response_rebound
            && self.exec_response_rebound
            && self.exec_request_identity_reused
            && self.close_stdin_request_identity_reused
            && self.operation_replayed_without_driver_dispatch == response_delivered
            && !self.cached_wait_replayed_without_driver_dispatch
            && self.first_operation_dispatches == 1
            && self.replacement_operation_dispatches == 1
            && self.host_stale_generation_rejected
            && self.guest_stale_generation_rejected
            && self.host_changed_request_rejected
            && !self.guest_changed_request_rejected
            && self.marker_reset_before_replacement
            && self.replacement_workload_verified
            && self.first_exec_marker_verified
            && self.exec_marker_reset_before_replacement
            && self.replacement_exec_marker_verified
            && self.first_close_marker_verified
            && self.close_marker_reset_before_replacement
            && self.replacement_close_marker_verified
            && self.force_delete_completed
            && !self.stopped_only_delete_completed
            && self.durable_records_empty
            && !self.delete_journal_succeeded_empty_after_reopen
            && self.marker_absent_after_cleanup
            && self.exec_marker_absent_after_cleanup
            && self.close_marker_absent_after_cleanup
            && self.first_guest_runtime_clean
            && self.replacement_guest_runtime_clean
            && self.owners_distinct
            && self.owner_identities_are_distinct()
            && self.state_root_removed
            && self.first_vm.is_success()
            && self.replacement_vm.is_success()
            && self.reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ContainerId, ErrorCode, Generation, OperationId, ProcessId};
    use serde_json::json;

    use super::OciVmOperationReopenReplacementReport;
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn close_stdin_report_requires_exact_replay_identity_markers_and_cleanup() {
        let mut report = OciVmOperationReopenReplacementReport::initial_close_stdin(
            HostPlatform::Macos,
            AgentTransportOperationStage::HostBeforeRequestWrite,
        );
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("reopen-close-stdin").expect("CloseStdin ID"));
        report.setup_create_operation_id =
            Some(OperationId::new("reopen-close-stdin-create").expect("Create ID"));
        report.setup_start_operation_id =
            Some(OperationId::new("reopen-close-stdin-start").expect("Start ID"));
        report.setup_exec_operation_id =
            Some(OperationId::new("reopen-close-stdin-exec").expect("Exec ID"));
        report.container_id = Some(ContainerId::new("reopen-close-stdin").expect("container ID"));
        report.exec_process_id = Some(ProcessId::new("worker").expect("process ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.close-stdin-host-before-request-write"
        ));
        report.fault_crossings = 1;
        report.first_operation_error_code = Some(ErrorCode::Unavailable);
        report.first_operation_error_operation =
            Some("oci-vm-transport-qualification-fault".to_string());
        report.first_operation_error_retryable = true;
        report.durable_running_retained = true;
        report.exec_journal_succeeded_before_reopen = true;
        report.close_stdin_journal_prepared_before_reopen = true;
        report.first_created_pid = Some(41);
        report.first_exec_pid = Some(6_201);
        report.generation_before_reopen = Some(Generation(1));
        report.host_service_reopened = true;
        report.replacement_recovery_calls = 1;
        report.replacement_rehydrated_created_record = true;
        report.replacement_rehydrated_running_record = true;
        report.replacement_rehydrated_exec_record = true;
        report.operation_completed_after_reopen = true;
        report.generation_after_reopen = Some(Generation(1));
        report.replacement_created_pid = Some(42);
        report.replacement_exec_pid = Some(6_202);
        report.replacement_response_matches_durable_record = true;
        report.same_generation_reused = true;
        report.setup_create_identity_reused = true;
        report.setup_start_identity_reused = true;
        report.same_operation_id_reused = true;
        report.setup_create_response_rebound = true;
        report.setup_start_response_rebound = true;
        report.exec_response_rebound = true;
        report.exec_request_identity_reused = true;
        report.close_stdin_request_identity_reused = true;
        report.first_operation_dispatches = 1;
        report.replacement_operation_dispatches = 1;
        report.host_stale_generation_rejected = true;
        report.guest_stale_generation_rejected = true;
        report.host_changed_request_rejected = true;
        report.marker_reset_before_replacement = true;
        report.replacement_workload_verified = true;
        report.first_exec_marker_verified = true;
        report.exec_marker_reset_before_replacement = true;
        report.replacement_exec_marker_verified = true;
        report.first_close_marker_verified = true;
        report.close_marker_reset_before_replacement = true;
        report.replacement_close_marker_verified = true;
        report.force_delete_completed = true;
        report.durable_records_empty = true;
        report.marker_absent_after_cleanup = true;
        report.exec_marker_absent_after_cleanup = true;
        report.close_marker_absent_after_cleanup = true;
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
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.close-stdin-{}",
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
                stage_report.first_response_matches_durable_record = true;
                stage_report.close_stdin_journal_prepared_before_reopen = false;
                stage_report.close_stdin_journal_succeeded_before_reopen = true;
                stage_report.replacement_rehydrated_close_stdin = true;
                stage_report.operation_replayed_without_driver_dispatch = true;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        for incomplete in [
            OciVmOperationReopenReplacementReport {
                replacement_rehydrated_exec_record: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                close_stdin_request_identity_reused: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                replacement_close_marker_verified: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                close_marker_absent_after_cleanup: false,
                ..report.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }
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
