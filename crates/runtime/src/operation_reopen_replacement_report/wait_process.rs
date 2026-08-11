use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::ExitStatus;

use super::{
    OciVmOperationReopenReplacementReport,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_PROCESS_SCHEMA_VERSION, QUALIFICATION_FAULT_OPERATION,
};

pub(crate) const WAIT_PROCESS_SIGNAL: i32 = 10;
pub(crate) const WAIT_PROCESS_TIMEOUT_MS: u64 = 15_000;

pub(crate) fn expected_wait_process_exit_status() -> ExitStatus {
    ExitStatus {
        exit_code: None,
        signal: Some(WAIT_PROCESS_SIGNAL),
        oom_killed: false,
    }
}

impl OciVmOperationReopenReplacementReport {
    pub(crate) fn initial_wait_process(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_state(platform, requested_stage);
        report.schema_version =
            OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_PROCESS_SCHEMA_VERSION.to_string();
        report.requested_operation = AgentOperation::WaitProcess;
        report.exec_terminal = Some(true);
        report.signal_process_signal = Some(WAIT_PROCESS_SIGNAL);
        report.wait_process_timeout_ms = Some(WAIT_PROCESS_TIMEOUT_MS);
        report.expected_exit_status = Some(expected_wait_process_exit_status());
        report
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported_wait_process(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_wait_process(platform, requested_stage);
        report.status = CapabilityStatus::Unsupported;
        report.first_vm.status = CapabilityStatus::Unsupported;
        report.first_vm.reason = Some("the first HVF owner was not started".to_string());
        report.replacement_vm.status = CapabilityStatus::Unsupported;
        report.replacement_vm.reason =
            Some("the replacement HVF owner was not started".to_string());
        report.reason = Some(
            "real utility-VM WaitProcess reopen and owner replacement is implemented only for macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    pub(super) fn wait_process_evidence_succeeded(&self) -> bool {
        let expected_point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::WaitProcess,
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
        let expected_exit = expected_wait_process_exit_status();
        let expected_first_exit = response_delivered.then_some(&expected_exit);
        let setup_ids_are_distinct = self
            .qualification_operation_id
            .as_ref()
            .zip(self.setup_create_operation_id.as_ref())
            .zip(self.setup_start_operation_id.as_ref())
            .zip(self.setup_exec_operation_id.as_ref())
            .zip(self.setup_signal_process_operation_id.as_ref())
            .is_some_and(|((((qualification, create), start), exec), signal)| {
                qualification != create
                    && qualification != start
                    && qualification != exec
                    && qualification != signal
                    && create != start
                    && create != exec
                    && create != signal
                    && start != exec
                    && start != signal
                    && exec != signal
            });

        matches!(self.platform, HostPlatform::Macos)
            && self.first_vm.platform == self.platform
            && self.replacement_vm.platform == self.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::WaitProcess
            && self.kill_signal.is_none()
            && self.kill_all.is_none()
            && self.delete_mode.is_none()
            && self.wait_timeout_ms.is_none()
            && self.wait_process_timeout_ms == Some(WAIT_PROCESS_TIMEOUT_MS)
            && self.expected_exit_status.as_ref() == Some(&expected_exit)
            && self.first_wait_exit_status.as_ref() == expected_first_exit
            && self.replacement_wait_exit_status.as_ref() == Some(&expected_exit)
            && self.cached_wait_exit_status.as_ref() == Some(&expected_exit)
            && self
                .exec_process_id
                .as_ref()
                .is_some_and(|process_id| !process_id.is_init())
            && self.exec_terminal == Some(true)
            && self.signal_process_signal == Some(WAIT_PROCESS_SIGNAL)
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
            && self.first_operation_response_received == response_delivered
            && self.disconnect_probe_attempted == response_delivered
            && !self.first_response_matches_durable_record
            && self.first_response_matches_expected_exit == response_delivered
            && !self.durable_created_retained
            && self.durable_running_retained
            && !self.durable_stopped_retained
            && !self.first_durable_records_empty
            && !self.delete_journal_prepared_before_reopen
            && !self.delete_journal_succeeded_empty_before_reopen
            && !self.init_exit_cached_before_reopen
            && !self.exec_journal_prepared_before_reopen
            && self.exec_journal_succeeded_before_reopen
            && !self.signal_process_journal_prepared_before_reopen
            && self.signal_process_journal_succeeded_before_reopen
            && self.process_exit_cached_before_reopen == response_delivered
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
            && self.replacement_rehydrated_signal_process
            && self.operation_completed_after_reopen
            && self.generation_before_reopen == self.generation_after_reopen
            && self.replacement_created_pid.is_some_and(|pid| pid > 0)
            && self.replacement_exec_pid.is_some_and(|pid| pid > 0)
            && !self.replacement_response_matches_durable_record
            && self.replacement_response_matches_expected_exit
            && self.cached_response_matches_expected_exit
            && !self.init_exit_cached_after_reopen
            && self.process_exit_cached_after_reopen
            && self.same_generation_reused
            && self.setup_create_identity_reused
            && self.setup_start_identity_reused
            && !self.setup_kill_identity_reused
            && !self.same_operation_id_reused
            && self.setup_create_response_rebound
            && self.setup_start_response_rebound
            && self.exec_response_rebound != response_delivered
            && self.exec_request_identity_reused
            && self.signal_process_request_identity_reused
            && self.wait_process_request_identity_reused
            && self.operation_replayed_without_driver_dispatch == response_delivered
            && self.cached_wait_replayed_without_driver_dispatch
            && self.first_operation_dispatches == 1
            && self.replacement_operation_dispatches == u32::from(!response_delivered)
            && self.host_stale_generation_rejected
            && self.guest_stale_generation_rejected
            && !self.host_changed_request_rejected
            && !self.guest_changed_request_rejected
            && self.marker_reset_before_replacement
            && self.replacement_workload_verified
            && self.first_exec_marker_verified
            && self.exec_marker_reset_before_replacement
            && self.replacement_exec_marker_verified
            && !self.first_signal_marker_verified
            && !self.signal_marker_reset_before_replacement
            && !self.replacement_signal_marker_verified
            && self.force_delete_completed
            && !self.stopped_only_delete_completed
            && self.durable_records_empty
            && !self.delete_journal_succeeded_empty_after_reopen
            && self.marker_absent_after_cleanup
            && self.exec_marker_absent_after_cleanup
            && !self.signal_marker_absent_after_cleanup
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

    use super::{expected_wait_process_exit_status, OciVmOperationReopenReplacementReport};
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn wait_process_report_requires_exit_cache_replay_and_exact_setup() {
        let mut report = OciVmOperationReopenReplacementReport::initial_wait_process(
            HostPlatform::Macos,
            AgentTransportOperationStage::HostBeforeRequestWrite,
        );
        let expected_exit = expected_wait_process_exit_status();
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id = Some(OperationId::new("wait-process").unwrap());
        report.setup_create_operation_id = Some(OperationId::new("wait-process-create").unwrap());
        report.setup_start_operation_id = Some(OperationId::new("wait-process-start").unwrap());
        report.setup_exec_operation_id = Some(OperationId::new("wait-process-exec").unwrap());
        report.setup_signal_process_operation_id =
            Some(OperationId::new("wait-process-signal").unwrap());
        report.container_id = Some(ContainerId::new("wait-process").unwrap());
        report.exec_process_id = Some(ProcessId::new("worker").unwrap());
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.wait-process-host-before-request-write"
        ));
        report.fault_crossings = 1;
        report.first_operation_error_code = Some(ErrorCode::Unavailable);
        report.first_operation_error_operation =
            Some("oci-vm-transport-qualification-fault".to_string());
        report.first_operation_error_retryable = true;
        report.durable_running_retained = true;
        report.exec_journal_succeeded_before_reopen = true;
        report.signal_process_journal_succeeded_before_reopen = true;
        report.first_created_pid = Some(41);
        report.first_exec_pid = Some(6_201);
        report.generation_before_reopen = Some(Generation(1));
        report.host_service_reopened = true;
        report.replacement_recovery_calls = 1;
        report.replacement_rehydrated_created_record = true;
        report.replacement_rehydrated_running_record = true;
        report.replacement_rehydrated_exec_record = true;
        report.replacement_rehydrated_signal_process = true;
        report.operation_completed_after_reopen = true;
        report.generation_after_reopen = Some(Generation(1));
        report.replacement_created_pid = Some(42);
        report.replacement_exec_pid = Some(6_202);
        report.replacement_wait_exit_status = Some(expected_exit.clone());
        report.cached_wait_exit_status = Some(expected_exit);
        report.replacement_response_matches_expected_exit = true;
        report.cached_response_matches_expected_exit = true;
        report.process_exit_cached_after_reopen = true;
        report.same_generation_reused = true;
        report.setup_create_identity_reused = true;
        report.setup_start_identity_reused = true;
        report.setup_create_response_rebound = true;
        report.setup_start_response_rebound = true;
        report.exec_response_rebound = true;
        report.exec_request_identity_reused = true;
        report.signal_process_request_identity_reused = true;
        report.wait_process_request_identity_reused = true;
        report.cached_wait_replayed_without_driver_dispatch = true;
        report.first_operation_dispatches = 1;
        report.replacement_operation_dispatches = 1;
        report.host_stale_generation_rejected = true;
        report.guest_stale_generation_rejected = true;
        report.marker_reset_before_replacement = true;
        report.replacement_workload_verified = true;
        report.first_exec_marker_verified = true;
        report.exec_marker_reset_before_replacement = true;
        report.replacement_exec_marker_verified = true;
        report.force_delete_completed = true;
        report.durable_records_empty = true;
        report.marker_absent_after_cleanup = true;
        report.exec_marker_absent_after_cleanup = true;
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
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.wait-process-{}",
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
                let expected_exit = expected_wait_process_exit_status();
                stage_report.first_operation_response_received = true;
                stage_report.disconnect_probe_attempted = true;
                stage_report.first_response_matches_expected_exit = true;
                stage_report.first_wait_exit_status = Some(expected_exit);
                stage_report.process_exit_cached_before_reopen = true;
                stage_report.exec_response_rebound = false;
                stage_report.operation_replayed_without_driver_dispatch = true;
                stage_report.replacement_operation_dispatches = 0;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        for incomplete in [
            OciVmOperationReopenReplacementReport {
                process_exit_cached_after_reopen: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                wait_process_request_identity_reused: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                replacement_rehydrated_signal_process: false,
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
