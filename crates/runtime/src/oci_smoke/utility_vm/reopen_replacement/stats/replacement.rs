use std::sync::Arc;

use a3s_oci_agent_protocol::AgentStatsRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    DeleteMode, DeleteRequest, ErrorCode, ListRequest, OciRuntimeService, OperationContext,
    StatsRequest,
};
use tokio::time::timeout;

use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::exec::support::{stale_target, wait_for_exact_marker};
use super::super::update::support::{update_journal_status, UpdateJournalStatus};
use super::super::{append_failure, owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::record_recovery_evidence;
use super::{FirstOwnerEvidence, Qualification, QualificationHvfDriver};
use crate::agent_session::UtilityVmSession;
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::oci_smoke::utility_vm::lifecycle::resource_stats_snapshot_is_exact;
use crate::{OciVmOperationReopenReplacementReport, RuntimeDriver};

pub(super) async fn run(
    qualification: &Qualification,
    first: &FirstOwnerEvidence,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<(), String> {
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
                "failed to launch the replacement Stats qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let driver = Arc::new(QualificationHvfDriver::with_update_recovery(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
        qualification.start.clone(),
        Some(qualification.update.clone()),
        Some((
            qualification.init_marker.clone(),
            qualification.init_marker_contents.clone(),
        )),
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
                "failed to reopen durable Host service around replacement Stats VM: {error}"
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
        || report.replacement_rehydrated_paused_record
        || report.replacement_rehydrated_resumed_record
        || !report.replacement_rehydrated_update
    {
        append_failure(
            &mut failure,
            "replacement driver did not rebuild the exact updated running state",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            "replacement Stats recovery did not retain only a positive init PID",
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
                || record.is_paused()
                || *record.state.pid() != report.replacement_created_pid
            {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement Stats recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered Stats record: {error}"),
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
        &qualification.init_marker,
        &qualification.init_marker_contents,
        "replacement Stats init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    let update_calls_before_replay = driver.update_calls();
    let replacement_update = match timeout(
        QUALIFICATION_TIMEOUT,
        service.update(qualification.update.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && record.generation
                    == qualification
                        .update
                        .target
                        .generation
                        .unwrap_or(record.generation)
                && *record.state.pid() == report.replacement_created_pid
                && driver.update_calls() == update_calls_before_replay =>
        {
            Some(record)
        }
        Ok(Ok(record)) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement Update replay did not bind to the rebuilt running record: {record:?}"
                ),
            );
            None
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement Update replay failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(&mut failure, "replacement Update replay timed out");
            None
        }
    };
    match update_journal_status(
        &qualification.state_root,
        &qualification.update.context.operation_id,
        &qualification.update.target,
    )
    .await
    {
        Ok(UpdateJournalStatus::Succeeded(journal))
            if replacement_update.as_ref() == Some(&journal)
                && *journal.state.pid() == report.replacement_created_pid
                && !journal.is_paused() =>
        {
            report.update_response_rebound = true;
            match service.list(ListRequest::default()).await {
                Ok(records) if records.as_slice() == [journal] => {}
                Ok(records) => append_failure(
                    &mut failure,
                    format!(
                        "replacement Update replay retained {} mismatched durable records",
                        records.len()
                    ),
                ),
                Err(error) => append_failure(
                    &mut failure,
                    format!("failed to inspect the replayed setup Update: {error}"),
                ),
            }
        }
        Ok(UpdateJournalStatus::Succeeded(_)) => append_failure(
            &mut failure,
            "replacement Update journal did not bind to the fresh init PID",
        ),
        Ok(UpdateJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement setup Update journal unexpectedly became prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_stats = driver.stats_calls();
    let replacement_snapshot = match timeout(
        QUALIFICATION_TIMEOUT,
        service.stats(qualification.stats.clone()),
    )
    .await
    {
        Ok(Ok(stats)) => {
            report.replacement_stats_verified =
                resource_stats_snapshot_is_exact(&stats, &qualification.update.target);
            report.operation_completed_after_reopen = report.replacement_stats_verified;
            report.generation_after_reopen = stats.target.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            report.stats_snapshot_rebound =
                report.first_stats_snapshot.as_ref().is_none_or(|first| {
                    stats.timestamp_unix_ns > first.timestamp_unix_ns && stats != *first
                });
            if !report.replacement_stats_verified {
                append_failure(
                    &mut failure,
                    "replacement Stats response did not match the rebuilt updated resource profile",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement Stats response changed the durable generation",
                );
            }
            if !report.stats_snapshot_rebound {
                append_failure(
                    &mut failure,
                    "replacement Stats response reused the first owner's snapshot",
                );
            }
            Some(stats)
        }
        Ok(Err(error)) => {
            append_failure(&mut failure, format!("replacement Stats failed: {error}"));
            None
        }
        Err(_) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement Stats exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            );
            None
        }
    };
    report.replacement_stats_snapshot = replacement_snapshot;
    report.operation_replayed_without_driver_dispatch = driver.stats_calls() == calls_before_stats;
    report.replacement_operation_dispatches = driver.stats_calls();
    if report.operation_replayed_without_driver_dispatch {
        append_failure(
            &mut failure,
            "replacement Stats query did not reach the replacement driver",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recorded {} Stats dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Update", driver.update_calls()),
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
    match driver.update_identity() {
        Ok(identity) => {
            report.update_request_identity_reused = identity == first.update_identity;
            if !report.update_request_identity_reused {
                append_failure(&mut failure, "replacement changed the setup Update request");
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.stats_identity() {
        Ok(identity) => {
            report.stats_request_target_reused =
                identity == first.stats_identity && identity == qualification.start.target;
            if !report.stats_request_target_reused {
                append_failure(
                    &mut failure,
                    "replacement Stats query changed its exact resolved target",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let stale = match stale_target(&qualification.start.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            qualification.start.target.clone()
        }
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().stats(AgentStatsRequest {
            target: stale.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong stale Stats error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(&mut failure, "replacement Guest accepted stale Stats"),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest stale Stats check timed out",
        ),
    }
    let calls_before_stale_host = driver.stats_calls();
    match service.stats(StatsRequest { target: stale }).await {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.stats_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong stale Stats error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened Host accepted stale Stats"),
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
