use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ListRequest, OciRuntimeService};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    append_failure, capture_recovery, path_absent, update_journal_status, wait_for_exact_marker,
    FirstOwnerOutcome, UpdateJournalStatus,
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
    let response_delivered =
        qualification.stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let recovery_update = response_delivered.then(|| first.update.clone());
    let recovery_update_ready_marker = response_delivered.then(|| {
        (
            first.init_marker.clone(),
            qualification.init_marker_contents.clone(),
        )
    });
    let driver = Arc::new(QualificationKvmOperationDriver::with_update_recovery(
        prepared,
        replacement_console.to_path_buf(),
        qualification.create.clone(),
        first.start.clone(),
        recovery_update,
        recovery_update_ready_marker,
    ));
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => {
                report.host_service_reopened = true;
                capture_recovery(&driver, report);
                service
            }
            Err(error) => {
                capture_recovery(&driver, report);
                report.replacement_vm = driver.shutdown().await;
                let cleanup = driver.cleanup(&first.target).await;
                report.marker_absent_after_cleanup =
                    path_absent(&first.init_marker).await.unwrap_or(false);
                return match cleanup {
                    Ok(()) => Err(format!("failed to reopen KVM Host service: {error}")),
                    Err(cleanup) => Err(format!(
                        "failed to reopen KVM Host service: {error}; {cleanup}"
                    )),
                };
            }
        };

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
        || report.replacement_rehydrated_paused_record
        || report.replacement_rehydrated_resumed_record
        || report.replacement_rehydrated_update != response_delivered
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the exact expected running Update state",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            "replacement KVM Update recovery did not retain only a positive init PID",
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
                || record.is_paused()
                || *record.state.pid() != report.replacement_created_pid
            {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM Update recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM Update recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM Update record: {error}"),
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
        &first.init_marker,
        &qualification.init_marker_contents,
        "replacement KVM Update init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_update = driver.update_calls();
    let replacement_response =
        match timeout(QUALIFICATION_TIMEOUT, service.update(first.update.clone())).await {
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
                        "replacement KVM Update changed the durable generation",
                    );
                }
                Some(record)
            }
            Ok(Ok(record)) => {
                append_failure(
                    &mut failure,
                    format!(
                    "replacement KVM Update returned invalid {} record with PID {:?} and paused={}",
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
                    format!("replacement KVM Update failed: {error}"),
                );
                None
            }
            Err(_) => {
                append_failure(&mut failure, "replacement KVM Update timed out");
                None
            }
        };
    report.operation_replayed_without_driver_dispatch =
        driver.update_calls() == calls_before_update;

    match update_journal_status(
        state_root,
        &first.update.context.operation_id,
        &first.target,
    )
    .await
    {
        Ok(UpdateJournalStatus::Succeeded(journal)) => {
            report.update_response_rebound = replacement_response.as_ref()
                == Some(journal.as_ref())
                && *journal.state.pid() == report.replacement_created_pid
                && !journal.is_paused();
            if !report.update_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement KVM Update journal did not bind to the fresh init PID",
                );
            }
            match service.list(ListRequest::default()).await {
                Ok(records) if records.as_slice() == std::slice::from_ref(journal.as_ref()) => {
                    report.replacement_response_matches_durable_record = true;
                }
                Ok(records) => append_failure(
                    &mut failure,
                    format!(
                        "completed KVM Update retained {} mismatched durable records",
                        records.len()
                    ),
                ),
                Err(error) => append_failure(
                    &mut failure,
                    format!("failed to inspect completed KVM Update record: {error}"),
                ),
            }
        }
        Ok(UpdateJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement KVM Update journal remained prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_replay = driver.update_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.update(first.update.clone())).await {
        Ok(Ok(record))
            if replacement_response.as_ref() == Some(&record)
                && driver.update_calls() == calls_before_replay => {}
        Ok(Ok(_)) => append_failure(
            &mut failure,
            "later KVM Update replay changed its response or reached the replacement driver",
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("later KVM Update replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "later KVM Update replay timed out"),
    }
    report.replacement_operation_dispatches = driver.update_calls();
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM Update dispatch did not match the durable journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} Update dispatches instead of one",
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
            report.setup_create_identity_reused = identity == first.create_identity;
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
            report.setup_start_identity_reused = identity == first.start_identity;
            if !report.setup_start_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup Start identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.update_identity() {
        Ok(identity) => {
            report.update_request_identity_reused = identity == first.update_identity;
            report.same_operation_id_reused = report.update_request_identity_reused
                && identity.context.operation_id == first.update.context.operation_id
                && identity.target == first.update.target
                && identity.resources == first.update.resources;
            if !report.update_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM Update changed its operation, target, or resource identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    super::validation::verify_update_effect_and_fences(
        &driver,
        &service,
        qualification,
        &first,
        report,
        &mut failure,
    )
    .await;

    match timeout(QUALIFICATION_TIMEOUT, service.delete(first.delete.clone())).await {
        Ok(Ok(())) => report.force_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM force Delete failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM force Delete timed out"),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM Delete retained {} durable records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect durable state after replacement KVM Delete: {error}"),
        ),
    }
    drop(service);
    report.replacement_vm = driver.shutdown().await;
    if let Err(reason) = driver.cleanup(&first.target).await {
        append_failure(&mut failure, reason);
    }
    match path_absent(&first.init_marker).await {
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
            "replacement KVM Update marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(&mut failure, "replacement KVM owner left its runtime share");
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM Update owner identities were not distinct",
        );
    }
    failure.map_or(Ok(()), Err)
}
