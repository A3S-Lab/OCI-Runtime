use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentTransportFaultInjector, AgentTransportFaultStage, AgentTransportOperationStage,
    AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ListRequest, OciRuntimeService, OperationContext, StartRequest,
};
use tokio::time::timeout;

use super::super::driver::QualificationKvmOperationDriver;
use super::super::exec::wait_for_exact_marker;
use super::super::mutation_support::{append_failure, record_interruption};
use super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::support::{
    active_failure, cleanup_failure, dispatch_host_mutation, driver_mutation_identity,
    mutation_calls, mutation_journal_status, response_matches, setup_failure,
    MutationJournalStatus,
};
use super::{FirstOwnerOutcome, Qualification};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::RuntimeDriver;
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<FirstOwnerOutcome, String> {
    let operation = qualification.mutation.agent_operation();
    let operation_id = qualification.mutation.operation_id()?.clone();
    let label = qualification.mutation.label();
    let faults = Arc::new(HostTransportFault::for_operation(
        operation,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let guest_qualification = if qualification.stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(operation_id, operation, qualification.stage)
                .map_err(|error| {
                format!("failed to construct Guest KVM {label} qualification: {error}")
            })?,
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
        qualification.create.clone(),
        Some(session_qualification),
    ));
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => service,
            Err(error) => {
                report.first_vm = driver.shutdown().await;
                return Err(format!(
                    "failed to open first KVM Host service for {label}: {error}"
                ));
            }
        };

    let created = match timeout(
        QUALIFICATION_TIMEOUT,
        service.create(qualification.create.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Created
                && record.state.id() == qualification.create.id.as_str()
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
                    "KVM {label} setup Create returned invalid {} record with PID {:?}",
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
                format!("KVM {label} setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                format!("KVM {label} setup Create timed out"),
            )
            .await;
        }
    };
    let target = ContainerTarget::exact(qualification.create.id.clone(), created.generation);
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
    let init_marker = match runtime_marker(&mount_root).await {
        Ok(marker) => marker,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    match path_absent(&init_marker).await {
        Ok(true) => {}
        Ok(false) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!(
                    "KVM {label} init marker existed before setup Start: {}",
                    init_marker.display()
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
        context: OperationContext::new(qualification.start_operation_id.clone()),
        target: target.clone(),
    };
    let started = match timeout(QUALIFICATION_TIMEOUT, service.start(start.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && record.generation == created.generation
                && record.state.id() == qualification.create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!(
                    "KVM {label} setup Start returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM {label} setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM {label} setup Start timed out"),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &init_marker,
        &qualification.init_marker_contents,
        &format!("first-owner KVM {label} init"),
    )
    .await
    {
        drop(service);
        return active_failure(&driver, &target, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(started.generation);

    let response_delivered =
        qualification.stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_host_mutation(&service, &qualification.mutation),
    )
    .await
    {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, qualification.stage, label) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!(
                "first KVM {label} unexpectedly completed before owner replacement: {response:?}"
            ),
        ),
        Err(_) => append_failure(&mut failure, format!("first KVM {label} timed out")),
    }
    match mutation_journal_status(state_root, &qualification.mutation, &target).await {
        Ok(MutationJournalStatus::Prepared) if !response_delivered => {}
        Ok(MutationJournalStatus::Succeeded(response)) if response_delivered => {
            report.first_response_matches_durable_record =
                response_matches(&response, &qualification.mutation, &target);
            if !report.first_response_matches_durable_record {
                append_failure(
                    &mut failure,
                    format!("first KVM {label} journal retained an invalid response: {response:?}"),
                );
            }
        }
        Ok(MutationJournalStatus::Prepared) => append_failure(
            &mut failure,
            format!("completed KVM {label} response left its Host journal prepared"),
        ),
        Ok(MutationJournalStatus::Succeeded(response)) => append_failure(
            &mut failure,
            format!(
                "KVM {label} Host journal committed before the selected response boundary: {response:?}"
            ),
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    report.first_operation_dispatches = mutation_calls(&driver, &qualification.mutation);
    if qualification.stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.durable_running_retained = record.state.id() == qualification.create.id.as_str()
                && record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.generation == created.generation
                && record.config_digest == created.config_digest
                && *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && *record.state.pid() == report.first_created_pid;
            if !report.durable_running_retained {
                append_failure(
                    &mut failure,
                    format!(
                        "interrupted KVM {label} did not retain the exact durable running record"
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM {label} retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect state after interrupted KVM {label}: {error}"),
        ),
    }

    let start_identity = driver.start_identity();
    let mutation_identity = driver_mutation_identity(&driver, &qualification.mutation);
    let expected_mutation_identity = qualification.mutation.exact_identity(&target);
    drop(service);
    report.first_vm = driver.shutdown().await;
    match runtime_entries_clean(&mount_root).await {
        Ok(clean) => report.first_guest_runtime_clean = clean,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if let Some(request) = guest_qualification.as_ref() {
        match read_guest_qualification_evidence(first_console, request).await {
            Ok(evidence) => {
                report.negotiated_protocol = Some(evidence.protocol_version());
                report.injected_point = Some(evidence.injected_point());
                report.fault_crossings = evidence.fault_crossings();
                report.guest_evidence_operation_id = Some(evidence.operation_id().clone());
                report.guest_evidence_verified = evidence.matches_request(request)
                    && evidence.protocol_version() == AGENT_PROTOCOL_VERSION_MAX
                    && evidence.fault_crossings() == 1;
                if !report.guest_evidence_verified {
                    append_failure(
                        &mut failure,
                        format!("Guest KVM {label} evidence did not match the exact qualification"),
                    );
                }
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    match reset_marker(&init_marker).await {
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
            format!("first KVM {label} owner left Guest Agent runtime state"),
        );
    }
    for (operation_name, calls) in [
        ("Start", driver.start_calls()),
        (label, report.first_operation_dispatches),
    ] {
        if calls != 1 {
            append_failure(
                &mut failure,
                format!(
                    "first KVM driver recorded {calls} {operation_name} dispatches instead of one"
                ),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM {label} point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let start_identity = start_identity.unwrap_or_else(|reason| {
        append_failure(&mut failure, reason);
        (start.context.operation_id.clone(), start.target.clone())
    });
    let mutation_identity = mutation_identity.unwrap_or_else(|reason| {
        append_failure(&mut failure, reason);
        expected_mutation_identity
    });
    if let Some(reason) = failure {
        return cleanup_failure(&driver, &target, reason).await;
    }
    drop(driver);
    Ok(FirstOwnerOutcome {
        target,
        mount_root,
        init_marker,
        create_identity,
        start_identity,
        mutation_identity,
        start,
        response_delivered,
    })
}
