use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentWaitProcessRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ErrorCode, ListRequest, OciRuntimeService, ProcessTarget, WaitProcessRequest};
use tokio::time::timeout;

use super::super::super::driver::{QualificationKvmOperationDriver, WaitProcessRecovery};
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    append_failure, exact_process_target, path_absent, process_exit_cache,
    signal_process_journal_status, stale_target, wait_for_exact_marker, FirstOwnerOutcome,
    SignalProcessJournalStatus,
};
use crate::driver::RuntimeDriver;
use crate::operation_journal_evidence::ProcessOperationJournalStatus;
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
    let expected_exit =
        crate::operation_reopen_replacement_report::wait_process::expected_wait_process_exit_status(
        );
    let driver = Arc::new(QualificationKvmOperationDriver::with_wait_process_recovery(
        prepared,
        replacement_console.to_path_buf(),
        qualification.create.clone(),
        first.start.clone(),
        first.exec.clone(),
        WaitProcessRecovery {
            signal_process: first.signal_process.clone(),
            signal_ready_marker: (
                first.exec_marker.clone(),
                qualification.exec_marker_contents.clone(),
            ),
            exec_is_live: !first.response_delivered,
        },
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
        || !report.replacement_rehydrated_signal_process
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild and terminate the exact WaitProcess Exec",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement KVM recovery did not retain positive init and Exec PIDs",
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
            {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM WaitProcess recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM WaitProcess recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM WaitProcess record: {error}"),
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
        "replacement KVM WaitProcess init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match wait_for_exact_marker(
        &first.exec_marker,
        &qualification.exec_marker_contents,
        "replacement KVM waitable Exec",
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
                if process.target == exact_process
                    && process.pid.is_some_and(|pid| pid > 0)
                    && process.terminal
                    && driver.exec_calls() == exec_calls_before_replay =>
            {
                Some(process)
            }
            Ok(Ok(process)) => {
                append_failure(
                    &mut failure,
                    format!("replacement KVM Exec replay returned invalid process {process:?}"),
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
    if let Some(process) = replacement_exec.as_ref() {
        match crate::operation_journal_evidence::process_operation_journal_status(
            state_root,
            &first.exec.context.operation_id,
            "exec",
            &exact_process,
        )
        .await
        {
            Ok(ProcessOperationJournalStatus::Succeeded(journal)) => {
                if first.response_delivered {
                    if process != &first.exec_record || journal != first.exec_record {
                        append_failure(
                            &mut failure,
                            "cached KVM WaitProcess changed the completed first-owner Exec response",
                        );
                    }
                } else {
                    report.exec_response_rebound =
                        process == &journal && process.pid == report.replacement_exec_pid;
                    if !report.exec_response_rebound {
                        append_failure(
                            &mut failure,
                            "replacement KVM WaitProcess Exec journal did not bind to the fresh PID",
                        );
                    }
                }
            }
            Ok(ProcessOperationJournalStatus::Prepared) => append_failure(
                &mut failure,
                "replacement KVM Exec journal remained prepared",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    match signal_process_journal_status(
        state_root,
        &first.signal_process.context.operation_id,
        &exact_process,
    )
    .await
    {
        Ok(SignalProcessJournalStatus::SucceededEmpty) => {}
        Ok(SignalProcessJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement KVM WaitProcess setup SignalProcess journal regressed to prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    match process_exit_cache(state_root, &exact_process).await {
        Ok((record, cache)) => {
            let expected_cache = first.response_delivered.then_some(&expected_exit);
            let expected_record = if first.response_delivered {
                &first.exec_record
            } else {
                replacement_exec.as_ref().unwrap_or(&first.exec_record)
            };
            if &record != expected_record || cache.as_ref() != expected_cache {
                append_failure(
                    &mut failure,
                    "KVM recovery did not preserve the exact preexisting process exit cache",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let wait_calls_before = driver.wait_process_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.wait_process(first.wait_process.clone()),
    )
    .await
    {
        Ok(Ok(status)) => {
            report.replacement_wait_exit_status = Some(status.clone());
            report.replacement_response_matches_expected_exit = status == expected_exit;
            report.operation_completed_after_reopen =
                report.replacement_response_matches_expected_exit;
            if !report.replacement_response_matches_expected_exit {
                append_failure(
                    &mut failure,
                    format!("replacement KVM WaitProcess returned unexpected status {status:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM WaitProcess failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM WaitProcess timed out"),
    }
    report.operation_replayed_without_driver_dispatch =
        driver.wait_process_calls() == wait_calls_before;
    match process_exit_cache(state_root, &exact_process).await {
        Ok((_, cache)) => {
            report.process_exit_cached_after_reopen = cache.as_ref() == Some(&expected_exit);
            if !report.process_exit_cached_after_reopen {
                append_failure(
                    &mut failure,
                    "replacement KVM WaitProcess did not persist the exact process exit cache",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_after_reopen = Some(record.generation);
            report.same_generation_reused = report.generation_before_reopen
                == report.generation_after_reopen
                && *record.state.status() == ContainerState::Running
                && *record.state.pid() == report.replacement_created_pid;
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM WaitProcess did not retain the running generation",
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM WaitProcess retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect replacement KVM WaitProcess state: {error}"),
        ),
    }

    let wait_calls_before_cache = driver.wait_process_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.wait_process(first.wait_process.clone()),
    )
    .await
    {
        Ok(Ok(status)) => {
            report.cached_wait_exit_status = Some(status.clone());
            report.cached_response_matches_expected_exit = status == expected_exit;
            if !report.cached_response_matches_expected_exit {
                append_failure(
                    &mut failure,
                    format!("cached KVM WaitProcess returned unexpected status {status:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("cached KVM WaitProcess replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "cached KVM WaitProcess replay timed out"),
    }
    report.cached_wait_replayed_without_driver_dispatch =
        driver.wait_process_calls() == wait_calls_before_cache;
    report.replacement_operation_dispatches = driver.wait_process_calls();
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM WaitProcess dispatch did not match the durable cache state",
        );
    }
    let expected_dispatches = u32::from(!first.response_delivered);
    if report.replacement_operation_dispatches != expected_dispatches {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} WaitProcess dispatches instead of {expected_dispatches}",
                report.replacement_operation_dispatches
            ),
        );
    }
    if !report.cached_wait_replayed_without_driver_dispatch {
        append_failure(
            &mut failure,
            "later KVM WaitProcess did not replay from the durable exit cache",
        );
    }
    match driver.wait_process_identity() {
        Ok(identity) if !first.response_delivered => {
            report.wait_process_request_identity_reused = identity == first.wait_process_identity;
            if !report.wait_process_request_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM WaitProcess changed its exact target or timeout",
                );
            }
        }
        Ok(_) => append_failure(
            &mut failure,
            "cache-backed replacement KVM WaitProcess unexpectedly reached the driver",
        ),
        Err(_) if first.response_delivered => report.wait_process_request_identity_reused = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    if driver.start_calls() != 1 || driver.exec_calls() != 1 || driver.signal_process_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM recovery recorded {} Start, {} Exec, and {} SignalProcess dispatches",
                driver.start_calls(),
                driver.exec_calls(),
                driver.signal_process_calls()
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
    match driver.exec_identity() {
        Ok(identity) => {
            report.exec_request_identity_reused = identity == first.exec_identity;
            if !report.exec_request_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup Exec identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.signal_process_identity() {
        Ok(identity) => {
            report.signal_process_request_identity_reused =
                identity == first.signal_process_identity;
            if !report.signal_process_request_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup SignalProcess identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let stale_container = match stale_target(&first.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            first.target.clone()
        }
    };
    let stale_process = ProcessTarget {
        container: stale_container,
        process_id: first.exec.process_id.clone(),
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        driver.guest_wait_process(AgentWaitProcessRequest {
            target: stale_process.clone(),
            timeout_ms: first.wait_process.timeout_ms,
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest returned the wrong stale WaitProcess error: {error}"),
        ),
        Ok(Ok(status)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest accepted stale WaitProcess with {status:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement KVM Guest stale WaitProcess check timed out",
        ),
    }
    let calls_before_stale_host = driver.wait_process_calls();
    match service
        .wait_process(WaitProcessRequest {
            process: stale_process,
            timeout_ms: first.wait_process.timeout_ms,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.wait_process_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong stale WaitProcess error: {error}"),
        ),
        Ok(status) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted stale WaitProcess with {status:?}"),
        ),
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
            "replacement KVM WaitProcess marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut failure,
            "replacement KVM WaitProcess owner left its runtime share",
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM WaitProcess owner identities were not distinct",
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
    report.replacement_created_pid = driver.rehydrated_running_pid();
    report.replacement_exec_pid = driver
        .rehydrated_exec_pid()
        .and_then(|pid| u32::try_from(pid).ok());
}
