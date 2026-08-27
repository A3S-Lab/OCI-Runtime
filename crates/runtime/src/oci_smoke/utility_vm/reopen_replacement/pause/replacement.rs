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
use super::support::{pause_journal_status, record_recovery_evidence, PauseJournalStatus};
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
                "failed to launch the replacement Pause qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let recovery_pause = response_delivered.then(|| qualification.pause.clone());
    let recovery_pause_ready_marker = response_delivered.then(|| {
        (
            qualification.marker.clone(),
            qualification.marker_contents.clone(),
        )
    });
    let driver = Arc::new(QualificationHvfDriver::with_pause_recovery(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
        qualification.start.clone(),
        recovery_pause,
        recovery_pause_ready_marker,
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
                "failed to reopen durable Host service around replacement Pause VM: {error}"
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
        || report.replacement_rehydrated_paused_record != response_delivered
    {
        append_failure(
            &mut failure,
            "replacement driver did not rebuild the exact expected running freezer state",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            "replacement Pause recovery did not retain only a positive init PID",
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
                || record.is_paused() != response_delivered
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
                "replacement Pause recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered Pause record: {error}"),
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
        "replacement Pause init readiness",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_pause = driver.pause_calls();
    let replacement_response = match timeout(
        QUALIFICATION_TIMEOUT,
        service.pause(qualification.pause.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && record.is_paused()
                && *record.state.pid() == report.replacement_created_pid =>
        {
            report.operation_completed_after_reopen = true;
            report.generation_after_reopen = Some(record.generation);
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement Pause did not retain the durable generation",
                );
            }
            Some(record)
        }
        Ok(Ok(record)) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement Pause returned invalid {} record with PID {:?} and paused={}",
                    record.state.status(),
                    record.state.pid(),
                    record.is_paused()
                ),
            );
            None
        }
        Ok(Err(error)) => {
            append_failure(&mut failure, format!("replacement Pause failed: {error}"));
            None
        }
        Err(_) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement Pause exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            );
            None
        }
    };
    report.operation_replayed_without_driver_dispatch = driver.pause_calls() == calls_before_pause;

    match pause_journal_status(
        &qualification.state_root,
        &qualification.pause.context.operation_id,
        &qualification.pause.target,
    )
    .await
    {
        Ok(PauseJournalStatus::Succeeded(journal)) => {
            report.pause_response_rebound = replacement_response.as_ref() == Some(&journal)
                && *journal.state.pid() == report.replacement_created_pid
                && journal.is_paused();
            if !report.pause_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement Pause journal did not bind to the fresh init PID",
                );
            }
            match service.list(ListRequest::default()).await {
                Ok(records) if records.as_slice() == std::slice::from_ref(journal.as_ref()) => {
                    report.replacement_response_matches_durable_record = true;
                }
                Ok(records) => append_failure(
                    &mut failure,
                    format!(
                        "completed Pause retained {} mismatched durable records",
                        records.len()
                    ),
                ),
                Err(error) => append_failure(
                    &mut failure,
                    format!("failed to inspect completed Pause record: {error}"),
                ),
            }
        }
        Ok(PauseJournalStatus::Prepared) => {
            append_failure(&mut failure, "replacement Pause journal remained prepared");
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_replay = driver.pause_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.pause(qualification.pause.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if replacement_response.as_ref() == Some(&record)
                && driver.pause_calls() == calls_before_replay => {}
        Ok(Ok(_)) => append_failure(
            &mut failure,
            "later Pause replay changed its response or reached the replacement driver",
        ),
        Ok(Err(error)) => {
            append_failure(&mut failure, format!("later Pause replay failed: {error}"));
        }
        Err(_) => append_failure(&mut failure, "later Pause replay timed out"),
    }
    report.replacement_operation_dispatches = driver.pause_calls();
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut failure,
            "replacement Pause dispatch did not match the durable journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recorded {} Pause dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if driver.start_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement recovery recorded {} Start dispatches instead of one",
                driver.start_calls()
            ),
        );
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
            report.pause_request_identity_reused = identity == first.pause_identity;
            report.same_operation_id_reused = report.pause_request_identity_reused
                && identity.0 == qualification.pause.context.operation_id
                && identity.1 == qualification.pause.target;
            if !report.pause_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement Pause changed its operation or target identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let changed_target = match stale_target(&qualification.pause.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            qualification.pause.target.clone()
        }
    };
    let changed_host = ContainerOperationRequest {
        context: qualification.pause.context.clone(),
        target: changed_target.clone(),
    };
    let calls_before_changed_host = driver.pause_calls();
    match service.pause(changed_host).await {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && driver.pause_calls() == calls_before_changed_host =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong changed Pause error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened Host accepted changed Pause"),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().pause(AgentContainerOperationRequest {
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
            format!("replacement Guest returned the wrong stale Pause error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(&mut failure, "replacement Guest accepted stale Pause"),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest stale Pause check timed out",
        ),
    }
    let calls_before_stale_host = driver.pause_calls();
    match service
        .pause(ContainerOperationRequest {
            context: OperationContext::new(qualification.stale_host_operation_id.clone()),
            target: changed_target,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.pause_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong stale Pause error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened Host accepted stale Pause"),
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
