use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerTarget, ListRequest, OciRuntimeService, OperationContext,
    StartRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    append_failure, identity_or_expected, path_absent, pause_journal_status, record_interruption,
    reset_marker, runtime_marker, wait_for_exact_marker, FirstOwnerOutcome, PauseJournalStatus,
};
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
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::Pause,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let guest_qualification = if qualification.stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                qualification.pause_operation_id.clone(),
                AgentOperation::Pause,
                qualification.stage,
            )
            .map_err(|error| format!("failed to construct Guest Pause qualification: {error}"))?,
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
                return Err(format!("failed to open first KVM Host service: {error}"));
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
                && !record.is_paused()
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
                    "KVM Pause setup Create returned invalid {} record with PID {:?} and paused={}",
                    record.state.status(),
                    record.state.pid(),
                    record.is_paused()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                format!("KVM Pause setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                "KVM Pause setup Create timed out".to_string(),
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
                    "KVM Pause marker existed before setup Start: {}",
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
                    "KVM Pause setup Start returned invalid {} record with PID {:?} and paused={}",
                    record.state.status(),
                    record.state.pid(),
                    record.is_paused()
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
                format!("KVM Pause setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Pause setup Start timed out".to_string(),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &marker,
        &qualification.marker_contents,
        "first-owner KVM Pause init readiness",
    )
    .await
    {
        drop(service);
        return active_failure(&driver, &target, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(started.generation);
    let start_identity = driver.start_identity();

    let pause = ContainerOperationRequest {
        context: OperationContext::new(qualification.pause_operation_id.clone()),
        target: target.clone(),
    };
    let response_delivered =
        qualification.stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(QUALIFICATION_TIMEOUT, service.pause(pause.clone())).await {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, qualification.stage) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(record)) => append_failure(
            &mut failure,
            format!("first KVM Pause unexpectedly completed before owner replacement: {record:?}"),
        ),
        Err(_) => append_failure(&mut failure, "first KVM Pause timed out"),
    }
    report.first_operation_dispatches = driver.pause_calls();
    if qualification.stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    let durable = match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = records.into_iter().next().expect("one record");
            report.durable_running_retained = record.state.id() == qualification.create.id.as_str()
                && record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.generation == created.generation
                && record.config_digest == created.config_digest
                && *record.state.status() == ContainerState::Running
                && *record.state.pid() == report.first_created_pid;
            report.durable_paused_retained = record.is_paused();
            if !report.durable_running_retained
                || report.durable_paused_retained != response_delivered
            {
                append_failure(
                    &mut failure,
                    "interrupted KVM Pause did not retain the exact expected running freezer state",
                );
            }
            Some(record)
        }
        Ok(records) => {
            append_failure(
                &mut failure,
                format!(
                    "interrupted KVM Pause retained {} records instead of one",
                    records.len()
                ),
            );
            None
        }
        Err(error) => {
            append_failure(
                &mut failure,
                format!("failed to inspect state after interrupted KVM Pause: {error}"),
            );
            None
        }
    };
    match pause_journal_status(state_root, &pause.context.operation_id, &pause.target).await {
        Ok(PauseJournalStatus::Prepared) => {
            report.pause_journal_prepared_before_reopen = true;
            if response_delivered {
                append_failure(
                    &mut failure,
                    "delivered KVM Pause response left its journal prepared",
                );
            }
        }
        Ok(PauseJournalStatus::Succeeded(journal)) => {
            report.pause_journal_succeeded_before_reopen = true;
            report.first_response_matches_durable_record =
                response_delivered && durable.as_ref() == Some(&journal);
            if !report.first_response_matches_durable_record {
                append_failure(
                    &mut failure,
                    "completed KVM Pause journal did not match its durable record",
                );
            }
            if !response_delivered {
                append_failure(
                    &mut failure,
                    "KVM Pause journal committed before its response boundary",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let pause_identity = driver.pause_identity();
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
                        "Guest Pause evidence did not match the exact KVM qualification",
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
            "first KVM Pause owner left Guest Agent runtime state",
        );
    }
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Pause", report.first_operation_dispatches),
    ] {
        if actual != 1 {
            append_failure(
                &mut failure,
                format!("first KVM driver recorded {actual} {label} dispatches instead of one"),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM Pause point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let start_identity = identity_or_expected(
        start_identity,
        &mut failure,
        (start.context.operation_id.clone(), start.target.clone()),
    );
    let pause_identity = identity_or_expected(
        pause_identity,
        &mut failure,
        (pause.context.operation_id.clone(), pause.target.clone()),
    );
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
        pause_identity,
        start,
        pause,
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
