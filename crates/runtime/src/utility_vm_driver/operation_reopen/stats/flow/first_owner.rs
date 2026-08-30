use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, ListRequest, OciRuntimeService, OperationContext,
    StartRequest, StateRequest, StatsRequest, UpdateRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    active_failure, append_failure, cleanup_failure, identity_or_expected, path_absent,
    record_interruption, reset_marker, runtime_marker, setup_failure, update_journal_status,
    wait_for_exact_marker, FirstOwnerOutcome, UpdateJournalStatus,
};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::{DriverUpdateRequest, RuntimeDriver};
use crate::oci_smoke::utility_vm::lifecycle::resource_stats_snapshot_is_exact;
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
        AgentOperation::Stats,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let guest_qualification = if qualification.stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                qualification.stats_operation_id.clone(),
                AgentOperation::Stats,
                qualification.stage,
            )
            .map_err(|error| {
                format!("failed to construct Guest KVM Stats qualification: {error}")
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
                    "KVM Stats setup Create returned invalid {} record with PID {:?}",
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
                format!("KVM Stats setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(&driver, report, "KVM Stats setup Create timed out".into()).await;
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
        Ok(root) => root,
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
                    "KVM Stats init marker existed before setup Start: {}",
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
                    "KVM Stats setup Start returned invalid {} record with PID {:?}",
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
                format!("KVM Stats setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Stats setup Start timed out".into(),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &init_marker,
        &qualification.init_marker_contents,
        "first-owner KVM Stats init",
    )
    .await
    {
        drop(service);
        return active_failure(&driver, &target, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(created.generation);

    let update = UpdateRequest {
        context: OperationContext::new(qualification.update_operation_id.clone()),
        target: target.clone(),
        resources: qualification.resources.clone(),
    };
    let updated = match timeout(QUALIFICATION_TIMEOUT, service.update(update.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && record.generation == created.generation
                && *record.state.pid() == report.first_created_pid =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM Stats setup Update returned an invalid record: {record:?}"),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM Stats setup Update failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Stats setup Update timed out".into(),
            )
            .await;
        }
    };
    match update_journal_status(state_root, &update.context.operation_id, &target).await {
        Ok(UpdateJournalStatus::Succeeded(journal)) if journal.as_ref() == &updated => {
            report.update_journal_succeeded_before_reopen = true;
        }
        Ok(UpdateJournalStatus::Succeeded(_)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Stats setup Update journal changed its durable response".into(),
            )
            .await;
        }
        Ok(UpdateJournalStatus::Prepared) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Stats setup Update journal remained prepared".into(),
            )
            .await;
        }
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    }

    let response_delivered =
        qualification.stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.stats(StatsRequest {
            target: qualification.stats_target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_interruption(report, error, qualification.stage) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(stats)) if response_delivered => {
            report.first_operation_response_received = true;
            report.first_stats_verified = resource_stats_snapshot_is_exact(&stats, &target);
            report.first_stats_snapshot = Some(stats);
            if !report.first_stats_verified {
                append_failure(
                    &mut failure,
                    "delivered first KVM Stats response did not match the updated profile",
                );
            }
            report.disconnect_probe_attempted = true;
            match timeout(
                QUALIFICATION_TIMEOUT,
                service.state(StateRequest {
                    target: target.clone(),
                }),
            )
            .await
            {
                Ok(Err(error)) => {
                    if let Err(reason) = record_interruption(report, error, qualification.stage) {
                        append_failure(&mut failure, reason);
                    }
                }
                Ok(Ok(_)) => append_failure(
                    &mut failure,
                    "KVM Stats disconnect probe unexpectedly succeeded",
                ),
                Err(_) => append_failure(&mut failure, "KVM Stats disconnect probe timed out"),
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("completed KVM Stats response was not delivered: {error}"),
        ),
        Ok(Ok(stats)) => append_failure(
            &mut failure,
            format!("first KVM Stats unexpectedly completed before replacement: {stats:?}"),
        ),
        Err(_) => append_failure(&mut failure, "first KVM Stats timed out"),
    }
    report.first_operation_dispatches = driver.stats_calls();
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
                    "interrupted KVM Stats changed the durable running record",
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM Stats retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect state after KVM Stats: {error}"),
        ),
    }

    let start_identity = driver.start_identity();
    let update_identity = driver.update_identity();
    let stats_identity = driver.stats_identity();
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
                        "Guest KVM Stats evidence did not match the exact qualification",
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
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Update", driver.update_calls()),
        ("Stats", report.first_operation_dispatches),
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
                "selected KVM Stats point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let start_identity = identity_or_expected(
        start_identity,
        &mut failure,
        (start.context.operation_id.clone(), start.target.clone()),
    );
    let expected_update = DriverUpdateRequest {
        context: update.context.clone(),
        target: update.target.clone(),
        resources: update.resources.clone(),
    };
    let update_identity = identity_or_expected(update_identity, &mut failure, expected_update);
    let stats_identity = identity_or_expected(stats_identity, &mut failure, target.clone());
    let delete = DeleteRequest {
        context: OperationContext::new(qualification.delete_operation_id.clone()),
        target: target.clone(),
        mode: DeleteMode::Force,
    };
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
        update_identity,
        stats_identity,
        start,
        update,
        delete,
    })
}
