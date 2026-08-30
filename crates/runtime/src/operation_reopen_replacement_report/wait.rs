use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::ExitStatus;

use super::{
    OciVmOperationReopenReplacementReport, OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_SCHEMA_VERSION,
    QUALIFICATION_FAULT_OPERATION,
};

const KILL_SIGNAL: i32 = 9;
pub(super) const WAIT_TIMEOUT_MS: u64 = 15_000;

pub(super) fn expected_wait_exit_status() -> ExitStatus {
    ExitStatus {
        exit_code: None,
        signal: Some(KILL_SIGNAL),
        oom_killed: false,
    }
}

impl OciVmOperationReopenReplacementReport {
    pub(crate) fn initial_wait(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_state(platform, requested_stage);
        report.schema_version = OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_SCHEMA_VERSION.to_string();
        report.requested_operation = AgentOperation::Wait;
        report.kill_signal = Some(KILL_SIGNAL);
        report.kill_all = Some(true);
        report.wait_timeout_ms = Some(WAIT_TIMEOUT_MS);
        report.expected_exit_status = Some(expected_wait_exit_status());
        report
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported_wait(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_wait(platform, requested_stage);
        report.status = CapabilityStatus::Unsupported;
        report.first_vm.status = CapabilityStatus::Unsupported;
        report.first_vm.reason = Some("the first HVF owner was not started".to_string());
        report.replacement_vm.status = CapabilityStatus::Unsupported;
        report.replacement_vm.reason =
            Some("the replacement HVF owner was not started".to_string());
        report.reason = Some(
            "real utility-VM Wait reopen and owner replacement is implemented only for macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    pub(super) fn wait_evidence_succeeded(&self) -> bool {
        let expected_point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::Wait,
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
        let expected_exit = expected_wait_exit_status();
        let expected_first_exit = response_delivered.then_some(&expected_exit);
        let setup_ids_are_distinct = self
            .setup_create_operation_id
            .as_ref()
            .zip(self.setup_start_operation_id.as_ref())
            .zip(self.setup_kill_operation_id.as_ref())
            .is_some_and(|((create, start), kill)| {
                create != start
                    && create != kill
                    && start != kill
                    && self.qualification_operation_id.as_ref() != Some(create)
                    && self.qualification_operation_id.as_ref() != Some(start)
                    && self.qualification_operation_id.as_ref() != Some(kill)
            });

        matches!(self.platform, HostPlatform::Macos | HostPlatform::Linux)
            && self.first_vm.platform == self.platform
            && self.replacement_vm.platform == self.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::Wait
            && self.kill_signal == Some(KILL_SIGNAL)
            && self.kill_all == Some(true)
            && self.delete_mode.is_none()
            && self.wait_timeout_ms == Some(WAIT_TIMEOUT_MS)
            && self.expected_exit_status.as_ref() == Some(&expected_exit)
            && (self.requested_stage.is_host() || guest_stage)
            && self.qualification_operation_id.is_some()
            && setup_ids_are_distinct
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
            && self.first_wait_exit_status.as_ref() == expected_first_exit
            && !self.durable_created_retained
            && !self.durable_running_retained
            && self.durable_stopped_retained
            && !self.first_durable_records_empty
            && !self.delete_journal_prepared_before_reopen
            && !self.delete_journal_succeeded_empty_before_reopen
            && self.init_exit_cached_before_reopen == response_delivered
            && self.first_created_pid.is_some_and(|pid| pid > 0)
            && self.generation_before_reopen.is_some()
            && expected_guest_evidence
            && self.host_service_reopened
            && self.replacement_recovery_calls == 1
            && self.replacement_rehydrated_created_record
            && self.replacement_rehydrated_running_record
            && self.replacement_rehydrated_stopped_record
            && self.operation_completed_after_reopen
            && self.generation_before_reopen == self.generation_after_reopen
            && self.replacement_created_pid.is_some_and(|pid| pid > 0)
            && !self.replacement_response_matches_durable_record
            && self.replacement_response_matches_expected_exit
            && self.cached_response_matches_expected_exit
            && self.replacement_wait_exit_status.as_ref() == Some(&expected_exit)
            && self.cached_wait_exit_status.as_ref() == Some(&expected_exit)
            && self.init_exit_cached_after_reopen
            && self.same_generation_reused
            && self.setup_create_identity_reused
            && self.setup_start_identity_reused
            && self.setup_kill_identity_reused
            && !self.same_operation_id_reused
            && !self.setup_create_response_rebound
            && !self.setup_start_response_rebound
            && self.operation_replayed_without_driver_dispatch == response_delivered
            && self.cached_wait_replayed_without_driver_dispatch
            && self.first_operation_dispatches == 1
            && self.replacement_operation_dispatches == u32::from(!response_delivered)
            && self.host_stale_generation_rejected
            && self.guest_stale_generation_rejected
            && self.marker_reset_before_replacement
            && self.replacement_workload_verified
            && !self.force_delete_completed
            && self.stopped_only_delete_completed
            && self.durable_records_empty
            && !self.delete_journal_succeeded_empty_after_reopen
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
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ContainerId, ErrorCode, Generation, OperationId};
    use serde_json::json;

    use super::{expected_wait_exit_status, OciVmOperationReopenReplacementReport};
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn wait_report_requires_terminal_cache_replay_and_stale_generation_fencing() {
        let mut report = OciVmOperationReopenReplacementReport::initial_wait(
            HostPlatform::Macos,
            AgentTransportOperationStage::HostBeforeRequestWrite,
        );
        let expected_exit = expected_wait_exit_status();
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("reopen-wait").expect("Wait nonce"));
        report.setup_create_operation_id =
            Some(OperationId::new("reopen-wait-create").expect("Create ID"));
        report.setup_start_operation_id =
            Some(OperationId::new("reopen-wait-start").expect("Start ID"));
        report.setup_kill_operation_id =
            Some(OperationId::new("reopen-wait-kill").expect("Kill ID"));
        report.container_id = Some(ContainerId::new("reopen-wait").expect("container ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.wait-host-before-request-write"
        ));
        report.fault_crossings = 1;
        report.first_operation_error_code = Some(ErrorCode::Unavailable);
        report.first_operation_error_operation =
            Some("oci-vm-transport-qualification-fault".to_string());
        report.first_operation_error_retryable = true;
        report.durable_stopped_retained = true;
        report.first_created_pid = Some(41);
        report.generation_before_reopen = Some(Generation(1));
        report.host_service_reopened = true;
        report.replacement_recovery_calls = 1;
        report.replacement_rehydrated_created_record = true;
        report.replacement_rehydrated_running_record = true;
        report.replacement_rehydrated_stopped_record = true;
        report.operation_completed_after_reopen = true;
        report.generation_after_reopen = Some(Generation(1));
        report.replacement_created_pid = Some(42);
        report.replacement_wait_exit_status = Some(expected_exit.clone());
        report.cached_wait_exit_status = Some(expected_exit);
        report.replacement_response_matches_expected_exit = true;
        report.cached_response_matches_expected_exit = true;
        report.init_exit_cached_after_reopen = true;
        report.same_generation_reused = true;
        report.setup_create_identity_reused = true;
        report.setup_start_identity_reused = true;
        report.setup_kill_identity_reused = true;
        report.cached_wait_replayed_without_driver_dispatch = true;
        report.first_operation_dispatches = 1;
        report.replacement_operation_dispatches = 1;
        report.host_stale_generation_rejected = true;
        report.guest_stale_generation_rejected = true;
        report.marker_reset_before_replacement = true;
        report.replacement_workload_verified = true;
        report.stopped_only_delete_completed = true;
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
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.wait-{}",
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
                let expected_exit = expected_wait_exit_status();
                stage_report.first_operation_response_received = true;
                stage_report.disconnect_probe_attempted = true;
                stage_report.first_response_matches_expected_exit = true;
                stage_report.first_wait_exit_status = Some(expected_exit);
                stage_report.init_exit_cached_before_reopen = true;
                stage_report.operation_replayed_without_driver_dispatch = true;
                stage_report.replacement_operation_dispatches = 0;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        let mut linux_report = report.clone();
        linux_report.platform = HostPlatform::Linux;
        linux_report.first_vm = complete_linux_bridge("first", 11, 12);
        linux_report.replacement_vm = complete_linux_bridge("replacement", 21, 22);
        for stage in AgentTransportOperationStage::ALL {
            let mut stage_report = linux_report.clone();
            stage_report.requested_stage = stage;
            stage_report.injected_point = Some(format!(
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.wait-{}",
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
                let expected_exit = expected_wait_exit_status();
                stage_report.first_operation_response_received = true;
                stage_report.disconnect_probe_attempted = true;
                stage_report.first_response_matches_expected_exit = true;
                stage_report.first_wait_exit_status = Some(expected_exit);
                stage_report.init_exit_cached_before_reopen = true;
                stage_report.operation_replayed_without_driver_dispatch = true;
                stage_report.replacement_operation_dispatches = 0;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        for incomplete in [
            OciVmOperationReopenReplacementReport {
                init_exit_cached_after_reopen: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                cached_wait_replayed_without_driver_dispatch: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                host_stale_generation_rejected: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                guest_stale_generation_rejected: false,
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

    fn complete_linux_bridge(name: &str, shim: u32, bridge: u32) -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Linux);
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
        report.guest_architecture = Some(std::env::consts::ARCH.into());
        report.advertised_operations = AgentOperation::ALL.to_vec();
        report.shim_report_verified = true;
        report.shim_exit_code = Some(0);
        report.console_created = true;
        report.shim_report = Some(json!({}));
        report
    }
}
