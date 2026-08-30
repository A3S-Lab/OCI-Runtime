use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode, ListRequest,
    OciRuntimeService, OperationContext, OperationId, StateRequest,
};
use tokio::time::timeout;

use super::super::driver::QualificationKvmOperationDriver;
use super::super::{
    owner_identities_are_distinct, runtime_entries_clean, QUALIFICATION_FAULT_OPERATION,
    QUALIFICATION_TIMEOUT,
};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::RuntimeDriver;
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    create: &CreateRequest,
    qualification_operation_id: &OperationId,
    delete_operation_id: &OperationId,
    stage: AgentTransportOperationStage,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<(), String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::State,
        AgentTransportFaultStage::from(stage),
    ));
    let guest_qualification = if stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                qualification_operation_id.clone(),
                AgentOperation::State,
                stage,
            )
            .map_err(|error| format!("failed to construct Guest State qualification: {error}"))?,
        )
    } else {
        None
    };
    let session_qualification = match guest_qualification.as_ref() {
        Some(qualification) => UtilityVmSessionQualification::Guest(qualification.clone()),
        None => UtilityVmSessionQualification::Host(
            Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>
        ),
    };

    let first_driver = Arc::new(QualificationKvmOperationDriver::new(
        prepared,
        first_console.to_path_buf(),
        create.clone(),
        Some(session_qualification),
    ));
    let first_service = HostRuntimeService::open(
        state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .map_err(|error| format!("failed to open first KVM Host service: {error}"))?;

    let created = match timeout(QUALIFICATION_TIMEOUT, first_service.create(create.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Created
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(first_service);
            return first_setup_failure(
                &first_driver,
                report,
                format!(
                    "KVM State setup returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(first_service);
            return first_setup_failure(
                &first_driver,
                report,
                format!("KVM State setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(first_service);
            return first_setup_failure(
                &first_driver,
                report,
                "KVM State setup Create timed out".to_string(),
            )
            .await;
        }
    };
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let first_create_identity = match first_driver.create_identity() {
        Ok(identity) => identity,
        Err(reason) => {
            drop(first_service);
            return first_active_failure(&first_driver, &target, report, reason).await;
        }
    };
    let mount_root = match first_driver.mount_root(&target).await {
        Ok(mount_root) => mount_root,
        Err(reason) => {
            drop(first_service);
            return first_active_failure(&first_driver, &target, report, reason).await;
        }
    };
    let state = StateRequest {
        target: target.clone(),
    };
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut first_response = None;
    let mut first_failure = None;
    match timeout(QUALIFICATION_TIMEOUT, first_service.state(state.clone())).await {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_interruption(report, error, stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Err(error)) => append_failure(
            &mut first_failure,
            format!(
                "{} did not deliver its completed KVM State response: {error}",
                stage.as_str()
            ),
        ),
        Ok(Ok(record)) if response_delivered => {
            report.first_operation_response_received = true;
            first_response = Some(record);
            report.disconnect_probe_attempted = true;
            match timeout(QUALIFICATION_TIMEOUT, first_service.state(state.clone())).await {
                Ok(Err(error)) => {
                    if let Err(reason) = record_interruption(report, error, stage) {
                        append_failure(&mut first_failure, reason);
                    }
                }
                Ok(Ok(_)) => append_failure(
                    &mut first_failure,
                    format!("{} disconnect probe unexpectedly succeeded", stage.as_str()),
                ),
                Err(_) => append_failure(
                    &mut first_failure,
                    format!("{} disconnect probe timed out", stage.as_str()),
                ),
            }
        }
        Ok(Ok(_)) => append_failure(
            &mut first_failure,
            "first KVM State unexpectedly completed before owner replacement",
        ),
        Err(_) => append_failure(&mut first_failure, "first KVM State timed out"),
    }
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    match first_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let durable = &records[0];
            report.generation_before_reopen = Some(durable.generation);
            report.first_created_pid = *durable.state.pid();
            report.durable_created_retained = durable.driver == DriverKind::LibkrunKvm
                && durable.isolation == IsolationClass::DedicatedVm
                && durable.state.id() == create.id.as_str()
                && *durable.state.status() == ContainerState::Created
                && durable.generation == created.generation
                && durable.config_digest == created.config_digest;
            report.first_response_matches_durable_record = first_response
                .as_ref()
                .is_some_and(|response| response == durable);
            if !report.durable_created_retained {
                append_failure(
                    &mut first_failure,
                    "interrupted KVM State did not retain the exact durable created record",
                );
            }
            if response_delivered && !report.first_response_matches_durable_record {
                append_failure(
                    &mut first_failure,
                    "delivered KVM State response differed from its durable record",
                );
            }
        }
        Ok(records) => append_failure(
            &mut first_failure,
            format!(
                "interrupted KVM State retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut first_failure,
            format!("failed to inspect interrupted KVM State: {error}"),
        ),
    }
    drop(first_service);
    report.first_vm = first_driver.shutdown().await;
    match runtime_entries_clean(&mount_root).await {
        Ok(clean) => report.first_guest_runtime_clean = clean,
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    if let Some(qualification) = guest_qualification.as_ref() {
        match read_guest_qualification_evidence(first_console, qualification).await {
            Ok(evidence) => {
                report.negotiated_protocol = Some(evidence.protocol_version());
                report.injected_point = Some(evidence.injected_point());
                report.fault_crossings = evidence.fault_crossings();
                report.guest_evidence_operation_id = Some(evidence.operation_id().clone());
                report.guest_evidence_verified = evidence.matches_request(qualification)
                    && evidence.protocol_version() == AGENT_PROTOCOL_VERSION_MAX
                    && evidence.fault_crossings() == 1;
                if !report.guest_evidence_verified {
                    append_failure(
                        &mut first_failure,
                        "Guest State evidence did not match the exact KVM qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut first_failure, reason),
        }
    }
    if !report.first_vm.is_success() {
        append_failure(
            &mut first_failure,
            report
                .first_vm
                .reason
                .clone()
                .unwrap_or_else(|| "first KVM VM cleanup evidence failed".to_string()),
        );
    }
    if !report.first_guest_runtime_clean {
        append_failure(
            &mut first_failure,
            "first KVM owner left Guest Agent runtime state",
        );
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "selected KVM State point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    if let Some(reason) = first_failure {
        return cleanup_failure(&first_driver, &target, reason).await;
    }
    drop(first_driver);

    let replacement_driver = Arc::new(QualificationKvmOperationDriver::new(
        prepared,
        replacement_console.to_path_buf(),
        create.clone(),
        None,
    ));
    let replacement_service = match HostRuntimeService::open(
        state_root,
        Arc::clone(&replacement_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => service,
        Err(error) => {
            report.replacement_recovery_calls = replacement_driver.recovery_calls();
            report.replacement_rehydrated_created_record =
                replacement_driver.rehydrated_created_record();
            report.replacement_vm = replacement_driver.shutdown().await;
            let cleanup = replacement_driver.cleanup(&target).await;
            return match cleanup {
                Ok(()) => Err(format!("failed to reopen KVM Host service: {error}")),
                Err(cleanup) => Err(format!(
                    "failed to reopen KVM Host service: {error}; {cleanup}"
                )),
            };
        }
    };
    report.host_service_reopened = true;
    report.replacement_recovery_calls = replacement_driver.recovery_calls();
    report.replacement_rehydrated_created_record = replacement_driver.rehydrated_created_record();
    let mut replacement_failure = None;
    if report.replacement_recovery_calls != 1 {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement KVM driver recovered {} records instead of one",
                report.replacement_recovery_calls
            ),
        );
    }
    if !report.replacement_rehydrated_created_record {
        append_failure(
            &mut replacement_failure,
            "replacement KVM driver did not rebuild the created process",
        );
    }
    let recovered = match replacement_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => Some(records[0].clone()),
        Ok(records) => {
            append_failure(
                &mut replacement_failure,
                format!(
                    "replacement KVM recovery retained {} records instead of one",
                    records.len()
                ),
            );
            None
        }
        Err(error) => {
            append_failure(
                &mut replacement_failure,
                format!("failed to inspect recovered KVM State record: {error}"),
            );
            None
        }
    };
    match timeout(QUALIFICATION_TIMEOUT, replacement_service.state(state)).await {
        Ok(Ok(record)) => {
            report.generation_after_reopen = Some(record.generation);
            report.replacement_created_pid = *record.state.pid();
            report.operation_completed_after_reopen =
                *record.state.status() == ContainerState::Created;
            report.replacement_response_matches_durable_record =
                recovered.as_ref() == Some(&record);
            report.same_generation_reused =
                report.generation_before_reopen == Some(record.generation);
            if !report.operation_completed_after_reopen {
                append_failure(
                    &mut replacement_failure,
                    "replacement KVM State did not observe created state",
                );
            }
            if !report.replacement_response_matches_durable_record {
                append_failure(
                    &mut replacement_failure,
                    "replacement KVM State response differed from durable state",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement KVM State observed a changed generation",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("replacement KVM State failed: {error}"),
        ),
        Err(_) => append_failure(&mut replacement_failure, "replacement KVM State timed out"),
    }
    match replacement_driver.create_identity() {
        Ok(replacement_identity) => {
            report.setup_create_identity_reused = replacement_identity == first_create_identity
                && replacement_identity.0 == create.context.operation_id
                && replacement_identity.1.generation == report.generation_before_reopen;
            if !report.setup_create_identity_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement KVM recovery changed the setup Create identity",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        replacement_service.delete(DeleteRequest {
            context: OperationContext::new(delete_operation_id.clone()),
            target: target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await
    {
        Ok(Ok(())) => report.force_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("replacement KVM force delete failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut replacement_failure,
            "replacement KVM force delete timed out",
        ),
    }
    match replacement_service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut replacement_failure,
                    format!(
                        "replacement KVM delete retained {} durable records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("failed to list after replacement KVM delete: {error}"),
        ),
    }
    drop(replacement_service);
    report.replacement_vm = replacement_driver.shutdown().await;
    if let Err(reason) = replacement_driver.cleanup(&target).await {
        append_failure(&mut replacement_failure, reason);
    }
    report.replacement_guest_runtime_clean = !mount_root.exists();
    report.owners_distinct =
        owner_identities_are_distinct(&report.first_vm, &report.replacement_vm);
    if !report.replacement_vm.is_success() {
        append_failure(
            &mut replacement_failure,
            report
                .replacement_vm
                .reason
                .clone()
                .unwrap_or_else(|| "replacement KVM VM cleanup evidence failed".to_string()),
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut replacement_failure,
            "replacement KVM owner left its runtime share",
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut replacement_failure,
            "first and replacement KVM owner identities were not distinct",
        );
    }
    replacement_failure.map_or(Ok(()), Err)
}

async fn first_setup_failure(
    driver: &QualificationKvmOperationDriver,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> std::result::Result<(), String> {
    report.first_vm = driver.shutdown().await;
    let cleanup = match driver.create_identity() {
        Ok((_, target)) => driver.cleanup(&target).await,
        Err(_) => Ok(()),
    };
    match cleanup {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}

async fn first_active_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> std::result::Result<(), String> {
    report.first_vm = driver.shutdown().await;
    cleanup_failure(driver, target, reason).await
}

async fn cleanup_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    reason: String,
) -> std::result::Result<(), String> {
    match driver.cleanup(target).await {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}

fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(QUALIFICATION_FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first KVM owner returned an unexpected State transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

fn append_failure(failure: &mut Option<String>, reason: impl Into<String>) {
    let reason = reason.into();
    *failure = Some(match failure.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}
