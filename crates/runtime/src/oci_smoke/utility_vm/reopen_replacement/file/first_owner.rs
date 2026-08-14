use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{FileRequest, ListRequest, OciRuntimeService};
use tokio::time::timeout;

use super::super::super::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::exec::support::{
    identity_or_expected, reset_marker, shutdown_setup_failure, wait_for_exact_marker,
};
use super::super::{append_failure, QUALIFICATION_TIMEOUT};
use super::support::{
    file_mutation_journal_status, record_interruption, upload_response_matches,
    FileMutationJournalStatus,
};
use super::{FirstOwnerEvidence, Qualification, QualificationHvfDriver};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::{OciVmOperationReopenReplacementReport, RuntimeDriver};

pub(super) async fn run(
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<FirstOwnerEvidence, String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::File,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let cleanup = MacosHostCleanupTracker::capture();
    let session_result = match qualification.guest_qualification.as_ref() {
        Some(request) => {
            crate::agent_session::UtilityVmSession::connect_with_guest_qualification(
                &qualification.shim,
                &qualification.vm_rootfs,
                Some(&qualification.system_image_manifest),
                &qualification.first_console,
                request,
            )
            .await
        }
        None => {
            crate::agent_session::UtilityVmSession::connect_with_host_fault_injector(
                &qualification.shim,
                &qualification.vm_rootfs,
                Some(&qualification.system_image_manifest),
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
                .unwrap_or_else(|| "failed to launch the first File qualification VM".to_string());
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
                "failed to open the first durable Host service for File: {error}"
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
                    "File setup Create returned invalid {} record with PID {:?}",
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
                format!("File setup Create failed: {error}"),
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
                    "File setup Create exceeded the {} second timeout",
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
                    "File setup Start returned invalid {} record with PID {:?}",
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
                format!("File setup Start failed: {error}"),
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
                    "File setup Start exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &qualification.init_marker,
        &qualification.init_marker_contents,
        "first-owner File init",
    )
    .await
    {
        return shutdown_setup_failure(service, driver, cleanup, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(started.generation);

    let response_delivered = qualification.stage
        == a3s_oci_agent_protocol::AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut first_failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.file(qualification.file.clone()),
    )
    .await
    {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, qualification.stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Ok(response)) => append_failure(
            &mut first_failure,
            format!("first File unexpectedly completed before owner replacement: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut first_failure,
            format!(
                "first File exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    match file_mutation_journal_status(
        &qualification.state_root,
        &qualification.file,
        &qualification.start.target,
    )
    .await
    {
        Ok(FileMutationJournalStatus::Prepared) if !response_delivered => {}
        Ok(FileMutationJournalStatus::Succeeded(response)) if response_delivered => {
            report.first_response_matches_durable_record = upload_response_matches(
                &response,
                &qualification.start.target,
                qualification.expected_payload.len(),
            );
            if !report.first_response_matches_durable_record {
                append_failure(
                    &mut first_failure,
                    format!("first File journal retained an invalid response: {response:?}"),
                );
            }
        }
        Ok(FileMutationJournalStatus::Prepared) => append_failure(
            &mut first_failure,
            "completed File response left its Host journal prepared",
        ),
        Ok(FileMutationJournalStatus::Succeeded(response)) => append_failure(
            &mut first_failure,
            format!(
                "File Host journal committed before the selected response boundary: {response:?}"
            ),
        ),
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    report.first_operation_dispatches = driver.file_calls();
    if qualification.stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.durable_running_retained = record.state.id() == qualification.create.id.as_str()
                && record.driver == DriverKind::LibkrunHvf
                && record.isolation == IsolationClass::DedicatedVm
                && record.generation == created.generation
                && record.config_digest == created.config_digest
                && *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && *record.state.pid() == report.first_created_pid;
            if !report.durable_running_retained {
                append_failure(
                    &mut first_failure,
                    "interrupted File did not retain the exact running record",
                );
            }
        }
        Ok(records) => append_failure(
            &mut first_failure,
            format!(
                "interrupted File retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut first_failure,
            format!("failed to inspect state after interrupted File: {error}"),
        ),
    }

    let expected_driver_file = FileRequest {
        target: qualification.start.target.clone(),
        ..qualification.file.clone()
    };
    let create_identity = driver.create_identity();
    let start_identity = driver.start_identity();
    let file_identity = driver.file_identity();

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
                        "Guest File evidence did not match the qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut first_failure, reason),
        }
    }
    match reset_marker(&qualification.init_marker).await {
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
        ("File", report.first_operation_dispatches),
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
                "selected File transport point crossed {} times instead of once",
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
    let file_identity =
        identity_or_expected(file_identity, &mut first_failure, expected_driver_file);
    if let Some(reason) = first_failure {
        return Err(reason);
    }
    drop(driver);
    drop(session);
    Ok(FirstOwnerEvidence {
        create_identity,
        start_identity,
        file_identity,
    })
}
