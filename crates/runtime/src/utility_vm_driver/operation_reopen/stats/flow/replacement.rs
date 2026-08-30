use std::path::Path;
use std::sync::Arc;

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
    let driver = Arc::new(QualificationKvmOperationDriver::with_update_recovery(
        prepared,
        replacement_console.to_path_buf(),
        qualification.create.clone(),
        first.start.clone(),
        Some(first.update.clone()),
        Some((
            first.init_marker.clone(),
            qualification.init_marker_contents.clone(),
        )),
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
        || !report.replacement_rehydrated_update
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the exact updated running Stats state",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            "replacement KVM Stats recovery did not retain only a positive init PID",
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
                        "replacement KVM Stats recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM Stats recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM Stats record: {error}"),
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
        "replacement KVM Stats init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let update_calls_before_replay = driver.update_calls();
    let replacement_update =
        match timeout(QUALIFICATION_TIMEOUT, service.update(first.update.clone())).await {
            Ok(Ok(record))
                if *record.state.status() == ContainerState::Running
                    && !record.is_paused()
                    && first.target.generation == Some(record.generation)
                    && *record.state.pid() == report.replacement_created_pid
                    && driver.update_calls() == update_calls_before_replay =>
            {
                Some(record)
            }
            Ok(Ok(record)) => {
                append_failure(
                    &mut failure,
                    format!("replacement KVM setup Update replay was invalid: {record:?}"),
                );
                None
            }
            Ok(Err(error)) => {
                append_failure(
                    &mut failure,
                    format!("replacement KVM setup Update replay failed: {error}"),
                );
                None
            }
            Err(_) => {
                append_failure(
                    &mut failure,
                    "replacement KVM setup Update replay timed out",
                );
                None
            }
        };
    match update_journal_status(
        state_root,
        &first.update.context.operation_id,
        &first.target,
    )
    .await
    {
        Ok(UpdateJournalStatus::Succeeded(journal))
            if replacement_update.as_ref() == Some(journal.as_ref())
                && *journal.state.pid() == report.replacement_created_pid
                && !journal.is_paused() =>
        {
            report.update_response_rebound = true;
            match service.list(ListRequest::default()).await {
                Ok(records) if records.as_slice() == std::slice::from_ref(journal.as_ref()) => {}
                Ok(records) => append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM setup Update retained {} mismatched records",
                        records.len()
                    ),
                ),
                Err(error) => append_failure(
                    &mut failure,
                    format!("failed to inspect replayed KVM setup Update: {error}"),
                ),
            }
        }
        Ok(UpdateJournalStatus::Succeeded(_)) => append_failure(
            &mut failure,
            "replacement KVM setup Update did not bind to the fresh init PID",
        ),
        Ok(UpdateJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement KVM setup Update journal became prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    if driver.update_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM recovery recorded {} Update dispatches instead of one",
                driver.update_calls()
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

    super::validation::verify_stats_and_fences(
        &driver,
        &service,
        qualification,
        &first,
        report,
        &mut failure,
    )
    .await;

    match driver.create_identity() {
        Ok(identity) => {
            report.setup_create_identity_reused = identity == first.create_identity;
            if !report.setup_create_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM changed setup Create identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.start_identity() {
        Ok(identity) => {
            report.setup_start_identity_reused = identity == first.start_identity;
            if !report.setup_start_identity_reused {
                append_failure(&mut failure, "replacement KVM changed setup Start identity");
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.update_identity() {
        Ok(identity) => {
            report.update_request_identity_reused = identity == first.update_identity;
            if !report.update_request_identity_reused {
                append_failure(&mut failure, "replacement KVM changed setup Update request");
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.stats_identity() {
        Ok(identity) => {
            report.stats_request_target_reused =
                identity == first.stats_identity && identity == first.target;
            if !report.stats_request_target_reused {
                append_failure(&mut failure, "replacement KVM changed exact Stats target");
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

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
            format!("failed to inspect durable state after KVM Delete: {error}"),
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
                .unwrap_or_else(|| "replacement KVM VM cleanup failed".to_string()),
        );
    }
    if !report.marker_absent_after_cleanup {
        append_failure(&mut failure, "replacement KVM Stats marker remained");
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut failure,
            "replacement KVM Stats owner left its runtime share",
        );
    }
    if !report.owners_distinct {
        append_failure(&mut failure, "KVM Stats owner identities were not distinct");
    }
    failure.map_or(Ok(()), Err)
}
