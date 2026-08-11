use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ListRequest, OciRuntimeService, StateRequest};
use tokio::time::timeout;

use super::super::super::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::exec::support::{
    identity_or_expected, reset_marker, shutdown_setup_failure, wait_for_exact_marker,
};
use super::super::{append_failure, QUALIFICATION_TIMEOUT};
use super::support::{pause_journal_status, record_interruption, PauseJournalStatus};
use super::{FirstOwnerEvidence, Qualification, QualificationHvfDriver};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::{OciVmOperationReopenReplacementReport, RuntimeDriver};

pub(super) async fn run(
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<FirstOwnerEvidence, String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::Pause,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let cleanup = MacosHostCleanupTracker::capture();
    let session_result = match qualification.guest_qualification.as_ref() {
        Some(request) => {
            crate::agent_session::UtilityVmSession::connect_with_guest_qualification(
                &qualification.shim,
                &qualification.vm_rootfs,
                &qualification.first_console,
                request,
            )
            .await
        }
        None => {
            crate::agent_session::UtilityVmSession::connect_with_host_fault_injector(
                &qualification.shim,
                &qualification.vm_rootfs,
                &qualification.first_console,
                Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>,
            )
            .await
        }
    };
    let session = match session_result {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            cleanup.apply(&mut bridge).await;
            let reason = bridge
                .reason
                .clone()
                .unwrap_or_else(|| "failed to launch the first Pause qualification VM".to_string());
            report.first_vm = bridge;
            return Err(reason);
        }
    };
    let driver = Arc::new(QualificationHvfDriver::new(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
    ));
    let service = match crate::HostRuntimeService::open(
        &qualification.state_root,
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => service,
        Err(error) => {
            report.first_vm = driver.shutdown().await;
            cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "failed to open the first durable Host service for Pause: {error}"
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
                && qualification.start.target.generation == Some(record.generation)
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!(
                    "Pause setup Create returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!("Pause setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!(
                    "Pause setup Create exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    };
    let started = match timeout(
        QUALIFICATION_TIMEOUT,
        service.start(qualification.start.clone()),
    )
    .await
    {
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
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!(
                    "Pause setup Start returned invalid {} record with PID {:?} and paused={}",
                    record.state.status(),
                    record.state.pid(),
                    record.is_paused()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!("Pause setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!(
                    "Pause setup Start exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &qualification.marker,
        &qualification.marker_contents,
        "first-owner Pause init readiness",
    )
    .await
    {
        return shutdown_setup_failure(service, driver, cleanup, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(started.generation);

    let response_delivered = qualification.stage
        == a3s_oci_agent_protocol::AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut first_response = None;
    let mut first_failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.pause(qualification.pause.clone()),
    )
    .await
    {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_interruption(report, error, qualification.stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Err(error)) => append_failure(
            &mut first_failure,
            format!(
                "{} did not deliver its completed Pause response: {error}",
                qualification.stage.as_str()
            ),
        ),
        Ok(Ok(record))
            if response_delivered
                && *record.state.status() == ContainerState::Running
                && record.is_paused()
                && *record.state.pid() == report.first_created_pid =>
        {
            report.first_operation_response_received = true;
            report.disconnect_probe_attempted = true;
            first_response = Some(record);
            match timeout(
                QUALIFICATION_TIMEOUT,
                service.state(StateRequest {
                    target: qualification.start.target.clone(),
                }),
            )
            .await
            {
                Ok(Err(error)) => {
                    if let Err(reason) = record_interruption(report, error, qualification.stage) {
                        append_failure(&mut first_failure, reason);
                    }
                }
                Ok(Ok(_)) => append_failure(
                    &mut first_failure,
                    format!(
                        "{} disconnect probe unexpectedly succeeded",
                        qualification.stage.as_str()
                    ),
                ),
                Err(_) => append_failure(
                    &mut first_failure,
                    format!(
                        "{} disconnect probe exceeded the {} second timeout",
                        qualification.stage.as_str(),
                        QUALIFICATION_TIMEOUT.as_secs()
                    ),
                ),
            }
        }
        Ok(Ok(record)) if response_delivered => append_failure(
            &mut first_failure,
            format!(
                "delivered Pause response returned invalid {} record with PID {:?} and paused={}",
                record.state.status(),
                record.state.pid(),
                record.is_paused()
            ),
        ),
        Ok(Ok(_)) => append_failure(
            &mut first_failure,
            "first Pause unexpectedly completed before owner replacement",
        ),
        Err(_) => append_failure(
            &mut first_failure,
            format!(
                "first Pause exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
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
                && record.driver == DriverKind::LibkrunHvf
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
                    &mut first_failure,
                    "interrupted Pause did not retain the exact expected running freezer state",
                );
            }
            Some(record)
        }
        Ok(records) => {
            append_failure(
                &mut first_failure,
                format!(
                    "interrupted Pause retained {} records instead of one",
                    records.len()
                ),
            );
            None
        }
        Err(error) => {
            append_failure(
                &mut first_failure,
                format!("failed to inspect state after interrupted Pause: {error}"),
            );
            None
        }
    };
    match pause_journal_status(
        &qualification.state_root,
        &qualification.pause.context.operation_id,
        &qualification.pause.target,
    )
    .await
    {
        Ok(PauseJournalStatus::Prepared) => {
            report.pause_journal_prepared_before_reopen = true;
            if response_delivered {
                append_failure(
                    &mut first_failure,
                    "delivered Pause response left its journal prepared",
                );
            }
        }
        Ok(PauseJournalStatus::Succeeded(journal)) => {
            report.pause_journal_succeeded_before_reopen = true;
            report.first_response_matches_durable_record = response_delivered
                && first_response.as_ref() == Some(&journal)
                && durable.as_ref() == Some(&journal);
            if !report.first_response_matches_durable_record {
                append_failure(
                    &mut first_failure,
                    "completed Pause journal did not match its response and durable record",
                );
            }
            if !response_delivered {
                append_failure(
                    &mut first_failure,
                    "Pause journal succeeded without a delivered response",
                );
            }
        }
        Err(reason) => append_failure(&mut first_failure, reason),
    }

    let create_identity = driver.create_identity();
    let start_identity = driver.start_identity();
    let pause_identity = driver.pause_identity();
    drop(service);
    report.first_vm = driver.shutdown().await;
    cleanup.apply(&mut report.first_vm).await;
    report.first_guest_runtime_clean = runtime_entries(&qualification.vm_rootfs)
        .await
        .is_ok_and(|entries| entries == qualification.baseline_runtime_entries);
    if let Some(request) = qualification.guest_qualification.as_ref() {
        match read_guest_qualification_evidence(&qualification.first_console, request).await {
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
                        &mut first_failure,
                        "Guest Pause evidence did not match the qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut first_failure, reason),
        }
    }
    match reset_marker(&qualification.marker).await {
        Ok(()) => report.marker_reset_before_replacement = true,
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    if !report.first_vm.is_success() {
        append_failure(
            &mut first_failure,
            report
                .first_vm
                .reason
                .clone()
                .unwrap_or_else(|| "first VM cleanup evidence failed".to_string()),
        );
    }
    if !report.first_guest_runtime_clean {
        append_failure(
            &mut first_failure,
            format!("first VM left {GUEST_RUNTIME_PREFIX} guest runtime state"),
        );
    }
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Pause", report.first_operation_dispatches),
    ] {
        if actual != 1 {
            append_failure(
                &mut first_failure,
                format!("first driver recorded {actual} {label} dispatches instead of one"),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "selected Pause transport point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let create_identity = identity_or_expected(
        create_identity,
        &mut first_failure,
        (
            qualification.create.context.operation_id.clone(),
            qualification.start.target.clone(),
        ),
    );
    let start_identity = identity_or_expected(
        start_identity,
        &mut first_failure,
        (
            qualification.start.context.operation_id.clone(),
            qualification.start.target.clone(),
        ),
    );
    let pause_identity = identity_or_expected(
        pause_identity,
        &mut first_failure,
        (
            qualification.pause.context.operation_id.clone(),
            qualification.pause.target.clone(),
        ),
    );
    if let Some(reason) = first_failure {
        return Err(reason);
    }
    drop(driver);
    drop(session);
    Ok(FirstOwnerEvidence {
        create_identity,
        start_identity,
        pause_identity,
    })
}
