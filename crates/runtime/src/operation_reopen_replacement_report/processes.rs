use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::ProcessRecord;

use super::{
    OciVmOperationReopenReplacementReport,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_PROCESSES_SCHEMA_VERSION, QUALIFICATION_FAULT_OPERATION,
};

impl OciVmOperationReopenReplacementReport {
    pub(crate) fn initial_processes(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_state(platform, requested_stage);
        report.schema_version =
            OCI_VM_OPERATION_REOPEN_REPLACEMENT_PROCESSES_SCHEMA_VERSION.to_string();
        report.requested_operation = AgentOperation::Processes;
        report.exec_terminal = Some(true);
        report
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported_processes(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_processes(platform, requested_stage);
        report.status = CapabilityStatus::Unsupported;
        report.first_vm.status = CapabilityStatus::Unsupported;
        report.first_vm.reason = Some("the first HVF owner was not started".to_string());
        report.replacement_vm.status = CapabilityStatus::Unsupported;
        report.replacement_vm.reason =
            Some("the replacement HVF owner was not started".to_string());
        report.reason = Some(
            "the generic utility-VM Processes reopen command is implemented for macOS aarch64/HVF; Linux KVM uses its dedicated qualification entry"
                .to_string(),
        );
        report
    }

    pub(super) fn processes_evidence_succeeded(&self) -> bool {
        let expected_point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::Processes,
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
            .is_some_and(|(((processes, create), start), exec)| {
                processes != create
                    && processes != start
                    && processes != exec
                    && create != start
                    && create != exec
                    && start != exec
            });
        let first_inventory_matches = self
            .first_process_inventory
            .as_deref()
            .zip(self.first_created_pid)
            .zip(self.first_exec_pid)
            .is_some_and(|((inventory, init_pid), exec_pid)| {
                self.inventory_matches(inventory, init_pid, exec_pid)
            });
        let replacement_inventory_matches = self
            .replacement_process_inventory
            .as_deref()
            .zip(self.replacement_created_pid)
            .zip(self.replacement_exec_pid)
            .is_some_and(|((inventory, init_pid), exec_pid)| {
                self.inventory_matches(inventory, init_pid, exec_pid)
            });

        matches!(self.platform, HostPlatform::Macos | HostPlatform::Linux)
            && self.first_vm.platform == self.platform
            && self.replacement_vm.platform == self.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::Processes
            && self.kill_signal.is_none()
            && self.kill_all.is_none()
            && self.delete_mode.is_none()
            && self.wait_timeout_ms.is_none()
            && self.wait_process_timeout_ms.is_none()
            && self.expected_exit_status.is_none()
            && self.first_wait_exit_status.is_none()
            && self.replacement_wait_exit_status.is_none()
            && self.cached_wait_exit_status.is_none()
            && self
                .exec_process_id
                .as_ref()
                .is_some_and(|process_id| !process_id.is_init())
            && self.exec_terminal == Some(true)
            && self.signal_process_signal.is_none()
            && (self.requested_stage.is_host() || guest_stage)
            && setup_ids_are_distinct
            && self.setup_kill_operation_id.is_none()
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
            && !self.first_response_matches_durable_record
            && !self.first_response_matches_expected_exit
            && self.first_process_inventory.is_some() == response_delivered
            && self.first_process_inventory_verified == response_delivered
            && first_inventory_matches == response_delivered
            && !self.durable_created_retained
            && self.durable_running_retained
            && !self.durable_paused_retained
            && !self.durable_stopped_retained
            && !self.first_durable_records_empty
            && !self.delete_journal_prepared_before_reopen
            && !self.delete_journal_succeeded_empty_before_reopen
            && !self.init_exit_cached_before_reopen
            && !self.exec_journal_prepared_before_reopen
            && self.exec_journal_succeeded_before_reopen
            && !self.signal_process_journal_prepared_before_reopen
            && !self.signal_process_journal_succeeded_before_reopen
            && !self.pause_journal_prepared_before_reopen
            && !self.pause_journal_succeeded_before_reopen
            && !self.resume_journal_prepared_before_reopen
            && !self.resume_journal_succeeded_before_reopen
            && !self.process_exit_cached_before_reopen
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
            && !self.replacement_rehydrated_signal_process
            && !self.replacement_rehydrated_paused_record
            && !self.replacement_rehydrated_resumed_record
            && self.operation_completed_after_reopen
            && self.generation_before_reopen == self.generation_after_reopen
            && self.replacement_created_pid.is_some_and(|pid| pid > 0)
            && self.replacement_exec_pid.is_some_and(|pid| pid > 0)
            && self.replacement_process_inventory.is_some()
            && self.replacement_process_inventory_verified
            && replacement_inventory_matches
            && self.process_inventory_rebound
            && !self.replacement_response_matches_durable_record
            && !self.replacement_response_matches_expected_exit
            && !self.cached_response_matches_expected_exit
            && !self.init_exit_cached_after_reopen
            && !self.process_exit_cached_after_reopen
            && self.same_generation_reused
            && self.setup_create_identity_reused
            && self.setup_start_identity_reused
            && !self.setup_kill_identity_reused
            && !self.same_operation_id_reused
            && self.setup_create_response_rebound
            && self.setup_start_response_rebound
            && self.exec_response_rebound
            && !self.pause_response_rebound
            && !self.resume_response_rebound
            && self.exec_request_identity_reused
            && !self.signal_process_request_identity_reused
            && !self.pause_request_identity_reused
            && !self.resume_request_identity_reused
            && self.processes_request_target_reused
            && !self.wait_process_request_identity_reused
            && !self.operation_replayed_without_driver_dispatch
            && !self.cached_wait_replayed_without_driver_dispatch
            && self.first_operation_dispatches == 1
            && self.replacement_operation_dispatches == 1
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

    fn inventory_matches(&self, inventory: &[ProcessRecord], init_pid: i32, exec_pid: u32) -> bool {
        let Some(container_id) = self.container_id.as_ref() else {
            return false;
        };
        let Some(generation) = self.generation_before_reopen else {
            return false;
        };
        let Ok(init_pid) = u32::try_from(init_pid) else {
            return false;
        };
        inventory.len() == 2
            && inventory.iter().all(|process| {
                process.target.container.id == *container_id
                    && process.target.container.generation == Some(generation)
                    && process.pid.is_some_and(|pid| pid > 0)
            })
            && inventory.iter().any(|process| {
                process.target.process_id.is_init()
                    && process.pid == Some(init_pid)
                    && !process.terminal
            })
            && self.exec_process_id.as_ref().is_some_and(|process_id| {
                inventory.iter().any(|process| {
                    &process.target.process_id == process_id
                        && process.pid == Some(exec_pid)
                        && process.terminal
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, ErrorCode, Generation, OperationId, ProcessId, ProcessRecord,
        ProcessTarget,
    };
    use serde_json::json;

    use super::OciVmOperationReopenReplacementReport;
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn processes_report_requires_exact_rebuilt_inventory_and_cleanup() {
        let mut report = OciVmOperationReopenReplacementReport::initial_processes(
            HostPlatform::Macos,
            AgentTransportOperationStage::HostBeforeRequestWrite,
        );
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("reopen-processes").expect("Processes nonce"));
        report.setup_create_operation_id =
            Some(OperationId::new("reopen-processes-create").expect("Create ID"));
        report.setup_start_operation_id =
            Some(OperationId::new("reopen-processes-start").expect("Start ID"));
        report.setup_exec_operation_id =
            Some(OperationId::new("reopen-processes-exec").expect("Exec ID"));
        let container_id = ContainerId::new("reopen-processes").expect("container ID");
        let container = ContainerTarget::exact(container_id.clone(), Generation(1));
        let process_id = ProcessId::new("worker").expect("process ID");
        report.container_id = Some(container_id);
        report.exec_process_id = Some(process_id.clone());
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.processes-host-before-request-write"
        ));
        report.fault_crossings = 1;
        report.first_operation_error_code = Some(ErrorCode::Unavailable);
        report.first_operation_error_operation =
            Some("oci-vm-transport-qualification-fault".to_string());
        report.first_operation_error_retryable = true;
        report.durable_running_retained = true;
        report.exec_journal_succeeded_before_reopen = true;
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
        report.replacement_process_inventory = Some(inventory(&container, &process_id, 42, 6_202));
        report.replacement_process_inventory_verified = true;
        report.process_inventory_rebound = true;
        report.same_generation_reused = true;
        report.setup_create_identity_reused = true;
        report.setup_start_identity_reused = true;
        report.setup_create_response_rebound = true;
        report.setup_start_response_rebound = true;
        report.exec_response_rebound = true;
        report.exec_request_identity_reused = true;
        report.processes_request_target_reused = true;
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
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.processes-{}",
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
                stage_report.first_process_inventory =
                    Some(inventory(&container, &process_id, 41, 6_201));
                stage_report.first_process_inventory_verified = true;
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
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.processes-{}",
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
                stage_report.first_process_inventory =
                    Some(inventory(&container, &process_id, 41, 6_201));
                stage_report.first_process_inventory_verified = true;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        for incomplete in [
            OciVmOperationReopenReplacementReport {
                replacement_rehydrated_exec_record: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                replacement_process_inventory_verified: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                process_inventory_rebound: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                processes_request_target_reused: false,
                ..report.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }
    }

    fn inventory(
        container: &ContainerTarget,
        process_id: &ProcessId,
        init_pid: u32,
        exec_pid: u32,
    ) -> Vec<ProcessRecord> {
        vec![
            ProcessRecord {
                target: ProcessTarget {
                    container: container.clone(),
                    process_id: ProcessId::init(),
                },
                pid: Some(init_pid),
                terminal: false,
            },
            ProcessRecord {
                target: ProcessTarget {
                    container: container.clone(),
                    process_id: process_id.clone(),
                },
                pid: Some(exec_pid),
                terminal: true,
            },
        ]
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
