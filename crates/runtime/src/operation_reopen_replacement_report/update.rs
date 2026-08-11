use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;

use super::{
    OciVmOperationReopenReplacementReport,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_UPDATE_SCHEMA_VERSION, QUALIFICATION_FAULT_OPERATION,
};

impl OciVmOperationReopenReplacementReport {
    pub(crate) fn initial_update(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_state(platform, requested_stage);
        report.schema_version =
            OCI_VM_OPERATION_REOPEN_REPLACEMENT_UPDATE_SCHEMA_VERSION.to_string();
        report.requested_operation = AgentOperation::Update;
        report
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported_update(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_update(platform, requested_stage);
        report.status = CapabilityStatus::Unsupported;
        report.first_vm.status = CapabilityStatus::Unsupported;
        report.first_vm.reason = Some("the first HVF owner was not started".to_string());
        report.replacement_vm.status = CapabilityStatus::Unsupported;
        report.replacement_vm.reason =
            Some("the replacement HVF owner was not started".to_string());
        report.reason = Some(
            "real utility-VM Update reopen and owner replacement is implemented only for macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    pub(super) fn update_evidence_succeeded(&self) -> bool {
        let expected_point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::Update,
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
            .is_some_and(|((update, create), start)| {
                update != create && update != start && create != start
            });
        let update_resources_are_exact = {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                crate::oci_smoke::utility_vm::lifecycle::resource_profile(HostPlatform::Macos)
                    .is_ok_and(|expected| self.update_resources.as_ref() == Some(&expected))
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            {
                false
            }
        };
        let update_stats_are_bound = self.replacement_update_stats.as_ref().is_some_and(|stats| {
            self.container_id.as_ref() == Some(&stats.target.id)
                && stats.target.generation == self.generation_after_reopen
                && {
                    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                    {
                        stats.memory.limit_bytes
                            == Some(crate::oci_smoke::utility_vm::lifecycle::UPDATED_MEMORY_LIMIT)
                    }
                    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                    {
                        false
                    }
                }
                && stats.timestamp_unix_ns > 0
                && stats.cpu.usage_ns > 0
                && stats.process_count >= 2
        });

        matches!(self.platform, HostPlatform::Macos)
            && self.first_vm.platform == self.platform
            && self.replacement_vm.platform == self.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::Update
            && update_resources_are_exact
            && self.kill_signal.is_none()
            && self.kill_all.is_none()
            && self.delete_mode.is_none()
            && self.wait_timeout_ms.is_none()
            && self.wait_process_timeout_ms.is_none()
            && self.expected_exit_status.is_none()
            && self.first_wait_exit_status.is_none()
            && self.replacement_wait_exit_status.is_none()
            && self.cached_wait_exit_status.is_none()
            && self.exec_process_id.is_none()
            && self.exec_terminal.is_none()
            && self.signal_process_signal.is_none()
            && (self.requested_stage.is_host() || guest_stage)
            && setup_ids_are_distinct
            && self.setup_kill_operation_id.is_none()
            && self.setup_exec_operation_id.is_none()
            && self.setup_signal_process_operation_id.is_none()
            && self.setup_pause_operation_id.is_none()
            && self.container_id.is_some()
            && self.negotiated_protocol == Some(AGENT_PROTOCOL_VERSION_MAX)
            && self.injected_point.as_deref() == Some(expected_point.as_str())
            && self.fault_crossings == 1
            && self.first_operation_error_code == Some(a3s_oci_sdk::ErrorCode::Unavailable)
            && expected_error_operation
            && self.first_operation_error_retryable
            && self.first_operation_response_received == response_delivered
            && self.disconnect_probe_attempted == response_delivered
            && self.first_response_matches_durable_record == response_delivered
            && !self.first_response_matches_expected_exit
            && !self.durable_created_retained
            && self.durable_running_retained
            && !self.durable_paused_retained
            && !self.durable_stopped_retained
            && !self.first_durable_records_empty
            && !self.delete_journal_prepared_before_reopen
            && !self.delete_journal_succeeded_empty_before_reopen
            && !self.init_exit_cached_before_reopen
            && !self.exec_journal_prepared_before_reopen
            && !self.exec_journal_succeeded_before_reopen
            && !self.signal_process_journal_prepared_before_reopen
            && !self.signal_process_journal_succeeded_before_reopen
            && !self.pause_journal_prepared_before_reopen
            && !self.pause_journal_succeeded_before_reopen
            && !self.resume_journal_prepared_before_reopen
            && !self.resume_journal_succeeded_before_reopen
            && self.update_journal_prepared_before_reopen != response_delivered
            && self.update_journal_succeeded_before_reopen == response_delivered
            && !self.process_exit_cached_before_reopen
            && self.first_created_pid.is_some_and(|pid| pid > 0)
            && self.first_exec_pid.is_none()
            && self.first_process_inventory.is_none()
            && self.generation_before_reopen.is_some()
            && expected_guest_evidence
            && self.host_service_reopened
            && self.replacement_recovery_calls == 1
            && self.replacement_rehydrated_created_record
            && self.replacement_rehydrated_running_record
            && !self.replacement_rehydrated_stopped_record
            && !self.replacement_rehydrated_exec_record
            && !self.replacement_rehydrated_signal_process
            && !self.replacement_rehydrated_paused_record
            && !self.replacement_rehydrated_resumed_record
            && self.replacement_rehydrated_update == response_delivered
            && self.operation_completed_after_reopen
            && self.generation_before_reopen == self.generation_after_reopen
            && self.replacement_created_pid.is_some_and(|pid| pid > 0)
            && self.replacement_exec_pid.is_none()
            && self.replacement_process_inventory.is_none()
            && self.replacement_response_matches_durable_record
            && !self.replacement_response_matches_expected_exit
            && !self.cached_response_matches_expected_exit
            && !self.init_exit_cached_after_reopen
            && !self.process_exit_cached_after_reopen
            && !self.first_process_inventory_verified
            && !self.replacement_process_inventory_verified
            && !self.process_inventory_rebound
            && self.replacement_update_effect_verified
            && update_stats_are_bound
            && self.same_generation_reused
            && self.setup_create_identity_reused
            && self.setup_start_identity_reused
            && !self.setup_kill_identity_reused
            && self.same_operation_id_reused
            && self.setup_create_response_rebound
            && self.setup_start_response_rebound
            && !self.exec_response_rebound
            && !self.pause_response_rebound
            && !self.resume_response_rebound
            && self.update_response_rebound
            && !self.exec_request_identity_reused
            && !self.signal_process_request_identity_reused
            && !self.pause_request_identity_reused
            && !self.resume_request_identity_reused
            && self.update_request_identity_reused
            && !self.processes_request_target_reused
            && !self.wait_process_request_identity_reused
            && self.operation_replayed_without_driver_dispatch == response_delivered
            && !self.cached_wait_replayed_without_driver_dispatch
            && self.first_operation_dispatches == 1
            && self.replacement_operation_dispatches == 1
            && self.host_stale_generation_rejected
            && self.guest_stale_generation_rejected
            && self.host_changed_request_rejected
            && self.guest_changed_request_rejected
            && self.marker_reset_before_replacement
            && self.replacement_workload_verified
            && !self.first_exec_marker_verified
            && !self.exec_marker_reset_before_replacement
            && !self.replacement_exec_marker_verified
            && !self.first_signal_marker_verified
            && !self.signal_marker_reset_before_replacement
            && !self.replacement_signal_marker_verified
            && self.force_delete_completed
            && !self.stopped_only_delete_completed
            && self.durable_records_empty
            && !self.delete_journal_succeeded_empty_after_reopen
            && self.marker_absent_after_cleanup
            && !self.exec_marker_absent_after_cleanup
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

#[cfg(all(
    test,
    any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ContainerId, ContainerStats, ErrorCode, Generation, OperationId};
    use serde_json::json;

    use super::OciVmOperationReopenReplacementReport;
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn update_report_requires_exact_resource_replay_stats_rebinds_and_cleanup() {
        let mut report = OciVmOperationReopenReplacementReport::initial_update(
            HostPlatform::Macos,
            AgentTransportOperationStage::HostBeforeRequestWrite,
        );
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("reopen-update").expect("Update ID"));
        report.setup_create_operation_id =
            Some(OperationId::new("reopen-update-create").expect("Create ID"));
        report.setup_start_operation_id =
            Some(OperationId::new("reopen-update-start").expect("Start ID"));
        report.container_id = Some(ContainerId::new("reopen-update").expect("container ID"));
        report.update_resources = Some(
            crate::oci_smoke::utility_vm::lifecycle::resource_profile(HostPlatform::Macos)
                .expect("macOS resource profile"),
        );
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.update-host-before-request-write"
        ));
        report.fault_crossings = 1;
        report.first_operation_error_code = Some(ErrorCode::Unavailable);
        report.first_operation_error_operation =
            Some("oci-vm-transport-qualification-fault".to_string());
        report.first_operation_error_retryable = true;
        report.durable_running_retained = true;
        report.update_journal_prepared_before_reopen = true;
        report.first_created_pid = Some(41);
        report.generation_before_reopen = Some(Generation(1));
        report.host_service_reopened = true;
        report.replacement_recovery_calls = 1;
        report.replacement_rehydrated_created_record = true;
        report.replacement_rehydrated_running_record = true;
        report.operation_completed_after_reopen = true;
        report.generation_after_reopen = Some(Generation(1));
        report.replacement_created_pid = Some(42);
        report.replacement_update_stats = Some(update_stats("reopen-update"));
        report.replacement_response_matches_durable_record = true;
        report.replacement_update_effect_verified = true;
        report.same_generation_reused = true;
        report.setup_create_identity_reused = true;
        report.setup_start_identity_reused = true;
        report.same_operation_id_reused = true;
        report.setup_create_response_rebound = true;
        report.setup_start_response_rebound = true;
        report.update_response_rebound = true;
        report.update_request_identity_reused = true;
        report.first_operation_dispatches = 1;
        report.replacement_operation_dispatches = 1;
        report.host_stale_generation_rejected = true;
        report.guest_stale_generation_rejected = true;
        report.host_changed_request_rejected = true;
        report.guest_changed_request_rejected = true;
        report.marker_reset_before_replacement = true;
        report.replacement_workload_verified = true;
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
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.update-{}",
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
                stage_report.update_journal_prepared_before_reopen = false;
                stage_report.update_journal_succeeded_before_reopen = true;
                stage_report.replacement_rehydrated_update = true;
                stage_report.operation_replayed_without_driver_dispatch = true;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        for incomplete in [
            OciVmOperationReopenReplacementReport {
                replacement_rehydrated_running_record: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                update_response_rebound: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                update_request_identity_reused: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                replacement_update_effect_verified: false,
                ..report.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }
    }

    fn update_stats(container: &str) -> ContainerStats {
        serde_json::from_value(json!({
            "target": {"id": container, "generation": 1},
            "timestamp_unix_ns": 1,
            "cpu": {
                "usage_ns": 1,
                "user_ns": 1,
                "system_ns": 0,
                "throttled_ns": 0
            },
            "memory": {
                "usage_bytes": 1,
                "limit_bytes": 536870912,
                "peak_bytes": 1
            },
            "process_count": 2,
            "metrics": {
                "memory.events.oom_kill": 0,
                "pids.events.max": 0
            }
        }))
        .expect("valid update Stats")
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
