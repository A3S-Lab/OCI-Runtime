use std::sync::Arc;

use a3s_oci_agent_protocol::AgentContainerOperationRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerOperationRequest, DeleteMode, DeleteRequest, ErrorCode, ListRequest,
    OciRuntimeService, OperationContext,
};
use tokio::time::timeout;

use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::exec::support::{stale_target, wait_for_exact_marker};
use super::super::{append_failure, owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{
    pause_journal_status, record_recovery_evidence, resume_journal_status, FreezerJournalStatus,
};
use super::{FirstOwnerEvidence, Qualification, QualificationHvfDriver};
use crate::agent_session::UtilityVmSession;
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::{OciVmOperationReopenReplacementReport, RuntimeDriver};

pub(super) async fn run(
    qualification: &Qualification,
    first: &FirstOwnerEvidence,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<(), String> {
    let response_delivered = qualification.stage
        == a3s_oci_agent_protocol::AgentTransportOperationStage::GuestAfterResponseWrite;
    let cleanup = MacosHostCleanupTracker::capture();
    let session = match UtilityVmSession::connect(
        &qualification.shim,
        &qualification.vm_rootfs,
        Some(&qualification.system_image_manifest),
        &qualification.replacement_console,
    )
    .await
    {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            cleanup.apply(&mut bridge).await;
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the replacement Resume qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let recovery_resume = response_delivered.then(|| qualification.resume.clone());
    let driver = Arc::new(QualificationHvfDriver::with_resume_recovery(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
        qualification.start.clone(),
        qualification.pause.clone(),
        (
            qualification.marker.clone(),
            qualification.marker_contents.clone(),
        ),
        recovery_resume,
    ));
    let service = match crate::HostRuntimeService::open(
        &qualification.state_root,
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => {
            report.host_service_reopened = true;
            record_recovery_evidence(report, &driver);
            service
        }
        Err(error) => {
            record_recovery_evidence(report, &driver);
            report.replacement_vm = driver.shutdown().await;
            cleanup.apply(&mut report.replacement_vm).await;
            return Err(format!(
                "failed to reopen durable Host service around replacement Resume VM: {error}"
            ));
        }
    };

    let mut failure = None;
    if report.replacement_recovery_calls != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recovered {} durable records instead of one",
                report.replacement_recovery_calls
            ),
        );
    }
    if !report.replacement_rehydrated_created_record
        || !report.replacement_rehydrated_running_record
        || report.replacement_rehydrated_stopped_record
        || report.replacement_rehydrated_exec_record
        || report.replacement_rehydrated_signal_process
        || !report.replacement_rehydrated_paused_record
        || report.replacement_rehydrated_resumed_record != response_delivered
    {
        append_failure(
            &mut failure,
            "replacement driver did not reconstruct the exact Pause-to-Resume freezer history",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            "replacement Resume recovery did not retain only a positive init PID",
        );
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            if record.state.id() != qualification.create.id.as_str()
                || qualification.start.target.generation != Some(record.generation)
                || record.driver != DriverKind::LibkrunHvf
                || record.isolation != IsolationClass::DedicatedVm
                || *record.state.status() != ContainerState::Running
                || *record.state.pid() != report.replacement_created_pid
                || record.is_paused() == response_delivered
            {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement recovery retained invalid {} record with PID {:?} and paused={}",
                        record.state.status(),
                        record.state.pid(),
                        record.is_paused()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement Resume recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered Resume record: {error}"),
        ),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.create(qualification.create.clone()),
    )
    .await
    {
        Ok(Ok(record)) => {
            report.setup_create_response_rebound = *record.state.status()
                == ContainerState::Created
                && !record.is_paused()
                && qualification.start.target.generation == Some(record.generation)
                && *record.state.pid() == report.replacement_created_pid;
            if !report.setup_create_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement Create replay did not bind to the fresh init PID",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Create journal replay failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!(
                "replacement Create replay exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.start(qualification.start.clone()),
    )
    .await
    {
        Ok(Ok(record)) => {
            report.setup_start_response_rebound = *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && qualification.start.target.generation == Some(record.generation)
                && *record.state.pid() == report.replacement_created_pid;
            if !report.setup_start_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement Start replay did not bind to the fresh init PID",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Start journal replay failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!(
                "replacement Start replay exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    match wait_for_exact_marker(
        &qualification.marker,
        &qualification.marker_contents,
        "replacement Resume init readiness",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let pause_calls_before_replay = driver.pause_calls();
    let pause_response = match timeout(
        QUALIFICATION_TIMEOUT,
        service.pause(qualification.pause.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && record.is_paused()
                && *record.state.pid() == report.replacement_created_pid
                && driver.pause_calls() == pause_calls_before_replay =>
        {
            Some(record)
        }
        Ok(Ok(record)) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement setup Pause replay returned invalid {} record with PID {:?}, paused={}, and {} extra dispatches",
                    record.state.status(),
                    record.state.pid(),
                    record.is_paused(),
                    driver.pause_calls().saturating_sub(pause_calls_before_replay)
                ),
            );
            None
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement setup Pause replay failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(&mut failure, "replacement setup Pause replay timed out");
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
        Ok(FreezerJournalStatus::Succeeded(journal)) => {
            report.pause_response_rebound = pause_response.as_ref() == Some(&journal)
                && *journal.state.pid() == report.replacement_created_pid
                && journal.is_paused();
            if !report.pause_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement Pause journal did not bind its historical response to the fresh init PID",
                );
            }
        }
        Ok(FreezerJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement setup Pause journal remained prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_resume = driver.resume_calls();
    let replacement_response = match timeout(
        QUALIFICATION_TIMEOUT,
        service.resume(qualification.resume.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && *record.state.pid() == report.replacement_created_pid =>
        {
            report.operation_completed_after_reopen = true;
            report.generation_after_reopen = Some(record.generation);
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement Resume did not retain the durable generation",
                );
            }
            Some(record)
        }
        Ok(Ok(record)) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement Resume returned invalid {} record with PID {:?} and paused={}",
                    record.state.status(),
                    record.state.pid(),
                    record.is_paused()
                ),
            );
            None
        }
        Ok(Err(error)) => {
            append_failure(&mut failure, format!("replacement Resume failed: {error}"));
            None
        }
        Err(_) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement Resume exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            );
            None
        }
    };
    report.operation_replayed_without_driver_dispatch =
        driver.resume_calls() == calls_before_resume;

    match resume_journal_status(
        &qualification.state_root,
        &qualification.resume.context.operation_id,
        &qualification.resume.target,
    )
    .await
    {
        Ok(FreezerJournalStatus::Succeeded(journal)) => {
            report.resume_response_rebound = replacement_response.as_ref() == Some(&journal)
                && *journal.state.pid() == report.replacement_created_pid
                && !journal.is_paused();
            if !report.resume_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement Resume journal did not bind to the fresh init PID",
                );
            }
            match service.list(ListRequest::default()).await {
                Ok(records) if records.as_slice() == [journal.clone()] => {
                    report.replacement_response_matches_durable_record = true;
                }
                Ok(records) => append_failure(
                    &mut failure,
                    format!(
                        "completed Resume retained {} mismatched durable records",
                        records.len()
                    ),
                ),
                Err(error) => append_failure(
                    &mut failure,
                    format!("failed to inspect completed Resume record: {error}"),
                ),
            }
        }
        Ok(FreezerJournalStatus::Prepared) => {
            append_failure(&mut failure, "replacement Resume journal remained prepared");
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_replay = driver.resume_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.resume(qualification.resume.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if replacement_response.as_ref() == Some(&record)
                && driver.resume_calls() == calls_before_replay => {}
        Ok(Ok(_)) => append_failure(
            &mut failure,
            "later Resume replay changed its response or reached the replacement driver",
        ),
        Ok(Err(error)) => {
            append_failure(&mut failure, format!("later Resume replay failed: {error}"));
        }
        Err(_) => append_failure(&mut failure, "later Resume replay timed out"),
    }
    report.replacement_operation_dispatches = driver.resume_calls();
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut failure,
            "replacement Resume dispatch did not match the durable journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recorded {} Resume dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Pause", driver.pause_calls()),
    ] {
        if actual != 1 {
            append_failure(
                &mut failure,
                format!("replacement recovery recorded {actual} {label} dispatches instead of one"),
            );
        }
    }

    match driver.create_identity() {
        Ok(identity) => {
            report.setup_create_identity_reused = identity == first.create_identity;
            if !report.setup_create_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement changed the setup Create identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.start_identity() {
        Ok(identity) => {
            report.setup_start_identity_reused = identity == first.start_identity;
            if !report.setup_start_identity_reused {
                append_failure(&mut failure, "replacement changed the setup Start identity");
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.pause_identity() {
        Ok(identity) => {
            report.pause_request_identity_reused = identity == first.pause_identity
                && identity.0 == qualification.pause.context.operation_id
                && identity.1 == qualification.pause.target;
            if !report.pause_request_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement changed the setup Pause operation or target identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.resume_identity() {
        Ok(identity) => {
            report.resume_request_identity_reused = identity == first.resume_identity;
            report.same_operation_id_reused = report.resume_request_identity_reused
                && identity.0 == qualification.resume.context.operation_id
                && identity.1 == qualification.resume.target;
            if !report.resume_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement Resume changed its operation or target identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let changed_target = match stale_target(&qualification.resume.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            qualification.resume.target.clone()
        }
    };
    let changed_host = ContainerOperationRequest {
        context: qualification.resume.context.clone(),
        target: changed_target.clone(),
    };
    let calls_before_changed_host = driver.resume_calls();
    match service.resume(changed_host).await {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && driver.resume_calls() == calls_before_changed_host =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong changed Resume error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened Host accepted changed Resume"),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().resume(AgentContainerOperationRequest {
            context: OperationContext::new(qualification.stale_guest_operation_id.clone()),
            target: changed_target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong stale Resume error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(&mut failure, "replacement Guest accepted stale Resume"),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest stale Resume check timed out",
        ),
    }
    let calls_before_stale_host = driver.resume_calls();
    match service
        .resume(ContainerOperationRequest {
            context: OperationContext::new(qualification.stale_host_operation_id.clone()),
            target: changed_target,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.resume_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong stale Resume error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened Host accepted stale Resume"),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.delete(DeleteRequest {
            context: OperationContext::new(qualification.delete_operation_id.clone()),
            target: qualification.start.target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await
    {
        Ok(Ok(())) => report.force_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement force delete failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!(
                "replacement force delete exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement delete retained {} durable container records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect state after replacement delete: {error}"),
        ),
    }
    drop(service);
    report.replacement_vm = driver.shutdown().await;
    cleanup.apply(&mut report.replacement_vm).await;
    report.replacement_guest_runtime_clean = runtime_entries(&qualification.vm_rootfs)
        .await
        .is_ok_and(|entries| entries == qualification.baseline_runtime_entries);
    report.owners_distinct =
        owner_identities_are_distinct(&report.first_vm, &report.replacement_vm);
    if !report.replacement_vm.is_success() {
        append_failure(
            &mut failure,
            report
                .replacement_vm
                .reason
                .clone()
                .unwrap_or_else(|| "replacement VM cleanup evidence failed".to_string()),
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut failure,
            format!("replacement VM left {GUEST_RUNTIME_PREFIX} guest runtime state"),
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement VM owner identities were not distinct",
        );
    }
    failure.map_or(Ok(()), Err)
}
