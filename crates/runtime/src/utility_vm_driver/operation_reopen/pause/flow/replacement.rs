use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentContainerOperationRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerOperationRequest, DeleteMode, DeleteRequest, ErrorCode, ListRequest,
    OciRuntimeService, OperationContext,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    append_failure, path_absent, pause_journal_status, stale_target, wait_for_exact_marker,
    FirstOwnerOutcome, PauseJournalStatus,
};
use crate::driver::RuntimeDriver;
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    replacement_console: &Path,
    qualification: &Qualification,
    first: FirstOwnerOutcome,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let recovery_pause = first.response_delivered.then(|| first.pause.clone());
    let recovery_pause_ready_marker = first
        .response_delivered
        .then(|| (first.marker.clone(), qualification.marker_contents.clone()));
    let driver = Arc::new(QualificationKvmOperationDriver::with_pause_recovery(
        prepared,
        replacement_console.to_path_buf(),
        qualification.create.clone(),
        first.start.clone(),
        recovery_pause,
        recovery_pause_ready_marker,
    ));
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => service,
            Err(error) => {
                capture_recovery(&driver, report);
                report.replacement_vm = driver.shutdown().await;
                let cleanup = driver.cleanup(&first.target).await;
                report.marker_absent_after_cleanup =
                    path_absent(&first.marker).await.unwrap_or(false);
                return match cleanup {
                    Ok(()) => Err(format!("failed to reopen KVM Host service: {error}")),
                    Err(cleanup) => Err(format!(
                        "failed to reopen KVM Host service: {error}; {cleanup}"
                    )),
                };
            }
        };
    report.host_service_reopened = true;
    capture_recovery(&driver, report);

    let mut failure = None;
    if report.replacement_recovery_calls != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recovered {} records instead of one",
                report.replacement_recovery_calls
            ),
        );
    }
    if !report.replacement_rehydrated_created_record
        || !report.replacement_rehydrated_running_record
        || report.replacement_rehydrated_stopped_record
        || report.replacement_rehydrated_exec_record
        || report.replacement_rehydrated_signal_process
        || report.replacement_rehydrated_paused_record != first.response_delivered
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the exact expected running freezer state",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            "replacement KVM Pause recovery did not retain only a positive init PID",
        );
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            if record.state.id() != qualification.create.id.as_str()
                || first.target.generation != Some(record.generation)
                || record.driver != DriverKind::LibkrunKvm
                || record.isolation != IsolationClass::DedicatedVm
                || *record.state.status() != ContainerState::Running
                || *record.state.pid() != report.replacement_created_pid
                || record.is_paused() != first.response_delivered
            {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM Pause recovery retained invalid {} record with PID {:?} and paused={}",
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
                "replacement KVM Pause recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM Pause record: {error}"),
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
                && first.target.generation == Some(record.generation)
                && *record.state.pid() == report.replacement_created_pid;
            if !report.setup_create_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement KVM Create replay did not bind to the fresh init PID",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Create journal replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Create replay timed out"),
    }
    match timeout(QUALIFICATION_TIMEOUT, service.start(first.start.clone())).await {
        Ok(Ok(record)) => {
            report.setup_start_response_rebound = *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && first.target.generation == Some(record.generation)
                && *record.state.pid() == report.replacement_created_pid;
            if !report.setup_start_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement KVM Start replay did not bind to the fresh init PID",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Start journal replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Start replay timed out"),
    }
    match wait_for_exact_marker(
        &first.marker,
        &qualification.marker_contents,
        "replacement KVM Pause init readiness",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_pause = driver.pause_calls();
    let replacement_response =
        match timeout(QUALIFICATION_TIMEOUT, service.pause(first.pause.clone())).await {
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
                        "replacement KVM Pause did not retain the durable generation",
                    );
                }
                Some(record)
            }
            Ok(Ok(record)) => {
                append_failure(
                    &mut failure,
                    format!(
                    "replacement KVM Pause returned invalid {} record with PID {:?} and paused={}",
                    record.state.status(),
                    record.state.pid(),
                    record.is_paused()
                ),
                );
                None
            }
            Ok(Err(error)) => {
                append_failure(
                    &mut failure,
                    format!("replacement KVM Pause failed: {error}"),
                );
                None
            }
            Err(_) => {
                append_failure(&mut failure, "replacement KVM Pause timed out");
                None
            }
        };
    report.operation_replayed_without_driver_dispatch = driver.pause_calls() == calls_before_pause;

    match pause_journal_status(
        state_root,
        &first.pause.context.operation_id,
        &first.pause.target,
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
                    "replacement KVM Pause journal did not bind to the fresh init PID",
                );
            }
            match service.list(ListRequest::default()).await {
                Ok(records) if records.as_slice() == std::slice::from_ref(journal.as_ref()) => {
                    report.replacement_response_matches_durable_record = true;
                }
                Ok(records) => append_failure(
                    &mut failure,
                    format!(
                        "completed KVM Pause retained {} mismatched durable records",
                        records.len()
                    ),
                ),
                Err(error) => append_failure(
                    &mut failure,
                    format!("failed to inspect completed KVM Pause record: {error}"),
                ),
            }
        }
        Ok(PauseJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement KVM Pause journal remained prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_replay = driver.pause_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.pause(first.pause.clone())).await {
        Ok(Ok(record))
            if replacement_response.as_ref() == Some(&record)
                && driver.pause_calls() == calls_before_replay => {}
        Ok(Ok(_)) => append_failure(
            &mut failure,
            "later KVM Pause replay changed its response or reached the replacement driver",
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("later KVM Pause replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "later KVM Pause replay timed out"),
    }
    report.replacement_operation_dispatches = driver.pause_calls();
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM Pause dispatch did not match the durable journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} Pause dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if driver.start_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM recovery recorded {} Start dispatches instead of one",
                driver.start_calls()
            ),
        );
    }

    match driver.create_identity() {
        Ok(identity) => {
            report.setup_create_identity_reused = identity == first.create_identity
                && identity.0 == qualification.create.context.operation_id
                && identity.1 == first.target;
            if !report.setup_create_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup Create identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.start_identity() {
        Ok(identity) => {
            report.setup_start_identity_reused = identity == first.start_identity
                && identity.0 == first.start.context.operation_id
                && identity.1 == first.start.target;
            if !report.setup_start_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup Start identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.pause_identity() {
        Ok(identity) => {
            report.pause_request_identity_reused = identity == first.pause_identity;
            report.same_operation_id_reused = report.pause_request_identity_reused
                && identity.0 == first.pause.context.operation_id
                && identity.1 == first.pause.target;
            if !report.pause_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM Pause changed its operation or target identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let changed_target = match stale_target(&first.pause.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            first.pause.target.clone()
        }
    };
    let changed_host = ContainerOperationRequest {
        context: first.pause.context.clone(),
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
            format!("reopened KVM Host returned the wrong changed Pause error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened KVM Host accepted changed Pause"),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        driver.guest_pause(AgentContainerOperationRequest {
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
            format!("replacement KVM Guest returned the wrong stale Pause error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(&mut failure, "replacement KVM Guest accepted stale Pause"),
        Err(_) => append_failure(
            &mut failure,
            "replacement KVM Guest stale Pause check timed out",
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
            format!("reopened KVM Host returned the wrong stale Pause error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened KVM Host accepted stale Pause"),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.delete(DeleteRequest {
            context: OperationContext::new(qualification.delete_operation_id.clone()),
            target: first.target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await
    {
        Ok(Ok(())) => report.force_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM force delete failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM force delete timed out"),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM delete retained {} durable records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut failure,
            format!("failed to list after replacement KVM delete: {error}"),
        ),
    }
    drop(service);
    report.replacement_vm = driver.shutdown().await;
    if let Err(reason) = driver.cleanup(&first.target).await {
        append_failure(&mut failure, reason);
    }
    match path_absent(&first.marker).await {
        Ok(absent) => report.marker_absent_after_cleanup = absent,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match path_absent(&first.mount_root).await {
        Ok(absent) => report.replacement_guest_runtime_clean = absent,
        Err(reason) => append_failure(&mut failure, reason),
    }
    report.owners_distinct =
        owner_identities_are_distinct(&report.first_vm, &report.replacement_vm);
    if !report.replacement_vm.is_success() {
        append_failure(
            &mut failure,
            report
                .replacement_vm
                .reason
                .clone()
                .unwrap_or_else(|| "replacement KVM VM cleanup evidence failed".to_string()),
        );
    }
    if !report.marker_absent_after_cleanup {
        append_failure(
            &mut failure,
            "replacement KVM Pause marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut failure,
            "replacement KVM Pause owner left its runtime share",
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM Pause owner identities were not distinct",
        );
    }
    failure.map_or(Ok(()), Err)
}

fn capture_recovery(
    driver: &QualificationKvmOperationDriver,
    report: &mut OciVmOperationReopenReplacementReport,
) {
    report.replacement_recovery_calls = driver.recovery_calls();
    report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
    report.replacement_rehydrated_running_record = driver.rehydrated_running_record();
    report.replacement_rehydrated_stopped_record = driver.rehydrated_stopped_record();
    report.replacement_rehydrated_exec_record = driver.rehydrated_exec_record();
    report.replacement_rehydrated_signal_process = driver.rehydrated_signal_process();
    report.replacement_rehydrated_paused_record = driver.rehydrated_paused_record();
    report.replacement_created_pid = driver.rehydrated_running_pid();
    report.replacement_exec_pid = driver
        .rehydrated_exec_pid()
        .and_then(|pid| u32::try_from(pid).ok());
}
