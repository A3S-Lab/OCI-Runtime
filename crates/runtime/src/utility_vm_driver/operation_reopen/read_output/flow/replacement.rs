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
    append_failure, capture_recovery, durable_exec_process, exact_process_target,
    exec_journal_status, path_absent, wait_for_exact_marker, ExecJournalStatus, FirstOwnerOutcome,
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
    let driver = Arc::new(QualificationKvmOperationDriver::with_exec_recovery(
        prepared,
        replacement_console.to_path_buf(),
        qualification.create.clone(),
        first.start.clone(),
        Some(first.exec.clone()),
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
                report.exec_marker_absent_after_cleanup =
                    path_absent(&first.exec_marker).await.unwrap_or(false);
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
        || !report.replacement_rehydrated_exec_record
        || report.replacement_rehydrated_signal_process
        || report.replacement_rehydrated_paused_record
        || report.replacement_rehydrated_resumed_record
        || report.replacement_rehydrated_update
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the exact live captured-output Exec",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement KVM ReadOutput recovery did not retain positive init and Exec PIDs",
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
                        "replacement KVM ReadOutput recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM ReadOutput recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM ReadOutput record: {error}"),
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
        "replacement KVM ReadOutput init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match wait_for_exact_marker(
        &first.exec_marker,
        &qualification.exec_marker_contents,
        "replacement KVM ReadOutput Exec",
    )
    .await
    {
        Ok(()) => report.replacement_exec_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let exact_process = exact_process_target(&first.exec);
    let exec_calls_before_replay = driver.exec_calls();
    let replacement_exec =
        match timeout(QUALIFICATION_TIMEOUT, service.exec(first.exec.clone())).await {
            Ok(Ok(process))
                if process.pid == report.replacement_exec_pid
                    && process.target == exact_process
                    && !process.terminal
                    && driver.exec_calls() == exec_calls_before_replay =>
            {
                report.exec_response_rebound = true;
                Some(process)
            }
            Ok(Ok(process)) => {
                append_failure(
                    &mut failure,
                    format!(
                    "replacement KVM Exec replay did not bind to the rebuilt process: {process:?}"
                ),
                );
                None
            }
            Ok(Err(error)) => {
                append_failure(
                    &mut failure,
                    format!("replacement KVM Exec replay failed: {error}"),
                );
                None
            }
            Err(_) => {
                append_failure(&mut failure, "replacement KVM Exec replay timed out");
                None
            }
        };
    match (
        exec_journal_status(state_root, &first.exec.context.operation_id, &exact_process).await,
        durable_exec_process(state_root, &exact_process).await,
    ) {
        (Ok(ExecJournalStatus::Succeeded(journal)), Ok(durable))
            if replacement_exec.as_ref() == Some(&journal)
                && replacement_exec.as_ref() == Some(&durable) => {}
        (Ok(ExecJournalStatus::Succeeded(_)), Ok(_)) => append_failure(
            &mut failure,
            "replacement KVM Exec journal did not bind to the rebuilt process",
        ),
        (Ok(ExecJournalStatus::Prepared), _) => append_failure(
            &mut failure,
            "replacement KVM ReadOutput recovery left its setup Exec journal prepared",
        ),
        (Err(reason), _) | (_, Err(reason)) => append_failure(&mut failure, reason),
    }

    super::validation::verify_output_and_fences(
        &driver,
        &service,
        qualification,
        &first,
        report,
        &mut failure,
    )
    .await;
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Exec", driver.exec_calls()),
    ] {
        if actual != 1 {
            append_failure(
                &mut failure,
                format!(
                    "replacement KVM recovery recorded {actual} {label} dispatches instead of one"
                ),
            );
        }
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
    match driver.exec_identity() {
        Ok(identity) => {
            report.exec_request_identity_reused = identity == first.exec_identity;
            if !report.exec_request_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup Exec request",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.read_output_identity() {
        Ok(identity) => {
            report.read_output_request_identity_reused = identity == first.read_output_identity;
            if !report.read_output_request_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM changed the complete ReadOutput request",
                );
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
    match path_absent(&first.exec_marker).await {
        Ok(absent) => report.exec_marker_absent_after_cleanup = absent,
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
    if !report.marker_absent_after_cleanup || !report.exec_marker_absent_after_cleanup {
        append_failure(
            &mut failure,
            "replacement KVM ReadOutput markers remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(&mut failure, "replacement KVM owner left its runtime share");
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM ReadOutput owner identities were not distinct",
        );
    }
    failure.map_or(Ok(()), Err)
}
