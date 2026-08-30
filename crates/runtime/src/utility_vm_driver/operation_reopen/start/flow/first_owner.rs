use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, ListRequest, OciRuntimeService, OperationContext, OperationId,
    StartRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::support::{
    append_failure, path_absent, record_interruption, reset_marker, runtime_marker,
    FirstOwnerOutcome,
};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::RuntimeDriver;
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::operation_journal_evidence::{
    container_operation_journal_status, ContainerOperationJournalStatus,
};
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    create: &CreateRequest,
    start_operation_id: &OperationId,
    stage: AgentTransportOperationStage,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<FirstOwnerOutcome, String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::Start,
        AgentTransportFaultStage::from(stage),
    ));
    let guest_qualification = if stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                start_operation_id.clone(),
                AgentOperation::Start,
                stage,
            )
            .map_err(|error| format!("failed to construct Guest Start qualification: {error}"))?,
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
    let driver = Arc::new(QualificationKvmOperationDriver::new(
        prepared,
        first_console.to_path_buf(),
        create.clone(),
        Some(session_qualification),
    ));
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => service,
            Err(error) => {
                report.first_vm = driver.shutdown().await;
                return Err(format!("failed to open first KVM Host service: {error}"));
            }
        };

    let created = match timeout(QUALIFICATION_TIMEOUT, service.create(create.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Created
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                format!(
                    "KVM Start setup returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                format!("KVM Start setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                "KVM Start setup Create timed out".to_string(),
            )
            .await;
        }
    };
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let create_identity = match driver.create_identity() {
        Ok(identity) => identity,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    let mount_root = match driver.mount_root(&target).await {
        Ok(mount_root) => mount_root,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    let marker = match runtime_marker(&mount_root).await {
        Ok(marker) => marker,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    match path_absent(&marker).await {
        Ok(true) => {}
        Ok(false) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!(
                    "KVM Start marker existed before the first Start: {}",
                    marker.display()
                ),
            )
            .await;
        }
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    }

    let start = StartRequest {
        context: OperationContext::new(start_operation_id.clone()),
        target: target.clone(),
    };
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(QUALIFICATION_TIMEOUT, service.start(start.clone())).await {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, stage) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(record)) => append_failure(
            &mut failure,
            format!("first KVM Start unexpectedly completed before owner replacement: {record:?}"),
        ),
        Err(_) => append_failure(&mut failure, "first KVM Start timed out"),
    }

    let first_response = match container_operation_journal_status(
        state_root,
        &start.context.operation_id,
        "start",
        &start.target,
    )
    .await
    {
        Ok(ContainerOperationJournalStatus::Prepared) if !response_delivered => None,
        Ok(ContainerOperationJournalStatus::Succeeded(response)) if response_delivered => {
            if *response.state.status() != ContainerState::Running {
                append_failure(
                    &mut failure,
                    format!(
                        "completed KVM Start journal retained {} instead of running",
                        response.state.status()
                    ),
                );
            }
            Some(response)
        }
        Ok(ContainerOperationJournalStatus::Prepared) => {
            append_failure(
                &mut failure,
                "completed KVM Start response left its Host journal prepared",
            );
            None
        }
        Ok(ContainerOperationJournalStatus::Succeeded(response)) => {
            append_failure(
                &mut failure,
                format!(
                    "KVM Start Host journal committed before its response boundary: {response:?}"
                ),
            );
            None
        }
        Err(reason) => {
            append_failure(&mut failure, reason);
            None
        }
    };
    report.first_operation_dispatches = driver.start_calls();
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_before_reopen = Some(record.generation);
            report.first_created_pid = *record.state.pid();
            let exact_record = record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.state.id() == create.id.as_str()
                && record.generation == created.generation
                && record.config_digest == created.config_digest;
            report.durable_created_retained =
                exact_record && *record.state.status() == ContainerState::Created;
            report.durable_running_retained =
                exact_record && *record.state.status() == ContainerState::Running;
            report.first_response_matches_durable_record = first_response
                .as_ref()
                .is_some_and(|response| response.as_ref() == record);
            let retained_expected = if response_delivered {
                report.durable_running_retained && report.first_response_matches_durable_record
            } else {
                report.durable_created_retained && !report.first_response_matches_durable_record
            };
            if !retained_expected {
                append_failure(
                    &mut failure,
                    format!(
                        "interrupted KVM Start retained {} instead of the exact durable {} record",
                        record.state.status(),
                        if response_delivered {
                            "running"
                        } else {
                            "created"
                        }
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM Start retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect interrupted KVM Start: {error}"),
        ),
    }
    let start_identity = driver.start_identity();
    drop(service);
    report.first_vm = driver.shutdown().await;
    match runtime_entries_clean(&mount_root).await {
        Ok(clean) => report.first_guest_runtime_clean = clean,
        Err(reason) => append_failure(&mut failure, reason),
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
                        &mut failure,
                        "Guest Start evidence did not match the exact KVM qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    match reset_marker(&marker).await {
        Ok(()) => report.marker_reset_before_replacement = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if !report.first_vm.is_success() {
        append_failure(
            &mut failure,
            report
                .first_vm
                .reason
                .clone()
                .unwrap_or_else(|| "first KVM VM cleanup evidence failed".to_string()),
        );
    }
    if !report.first_guest_runtime_clean {
        append_failure(
            &mut failure,
            "first KVM owner left Guest Agent runtime state",
        );
    }
    if report.first_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "first KVM driver recorded {} Start dispatches instead of one",
                report.first_operation_dispatches
            ),
        );
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM Start point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let start_identity = match start_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut failure, reason);
            (start.context.operation_id.clone(), start.target.clone())
        }
    };
    if let Some(reason) = failure {
        return cleanup_failure(&driver, &target, reason).await;
    }
    drop(driver);
    Ok(FirstOwnerOutcome {
        target,
        mount_root,
        marker,
        create_identity,
        start_identity,
        start,
        response_delivered,
    })
}

async fn setup_failure(
    driver: &QualificationKvmOperationDriver,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
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

async fn active_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    report.first_vm = driver.shutdown().await;
    cleanup_failure(driver, target, reason).await
}

async fn cleanup_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    match driver.cleanup(target).await {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}
