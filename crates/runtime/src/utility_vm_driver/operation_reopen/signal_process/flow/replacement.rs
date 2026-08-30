use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentSignalProcessRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ErrorCode, ListRequest, OciRuntimeService, OperationContext, ProcessTarget, Signal,
    SignalProcessRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::exec::{exact_process_target, stale_target, wait_for_exact_marker};
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    append_failure, durable_exec_process, path_absent, signal_process_journal_status,
    FirstOwnerOutcome, SignalProcessJournalStatus,
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
    let recovery_signal = first
        .response_delivered
        .then(|| first.signal_process.clone());
    let recovery_ready_marker = first.response_delivered.then(|| {
        (
            first.exec_marker.clone(),
            qualification.exec_marker_contents.clone(),
        )
    });
    let driver = Arc::new(
        QualificationKvmOperationDriver::with_signal_process_recovery(
            prepared,
            replacement_console.to_path_buf(),
            qualification.create.clone(),
            first.start.clone(),
            first.exec.clone(),
            recovery_signal,
            recovery_ready_marker,
        ),
    );
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
                report.signal_marker_absent_after_cleanup =
                    path_absent(&first.signal_marker).await.unwrap_or(false);
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
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the exact running init and Exec processes",
        );
    }
    if report.replacement_rehydrated_signal_process != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM signal replay did not match the durable journal outcome",
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
                        "replacement KVM SignalProcess recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM SignalProcess recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM SignalProcess record: {error}"),
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
        "replacement KVM SignalProcess init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match wait_for_exact_marker(
        &first.exec_marker,
        &qualification.exec_marker_contents,
        "replacement KVM signalable Exec",
    )
    .await
    {
        Ok(()) => report.replacement_exec_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let exact_process = exact_process_target(&first.exec);
    let exec_calls_before_replay = driver.exec_calls();
    let replacement_exec = match timeout(QUALIFICATION_TIMEOUT, service.exec(first.exec.clone()))
        .await
    {
        Ok(Ok(process))
            if process.target == exact_process
                && process.pid.is_some_and(|pid| pid > 0)
                && process.terminal
                && driver.exec_calls() == exec_calls_before_replay =>
        {
            report.replacement_exec_pid = process.pid;
            Some(process)
        }
        Ok(Ok(process)) => {
            append_failure(
                &mut failure,
                format!("replacement KVM setup Exec replay returned invalid process {process:?}"),
            );
            None
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement KVM setup Exec replay failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(&mut failure, "replacement KVM setup Exec replay timed out");
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
                report.exec_response_rebound =
                    process == &journal && process.pid == report.replacement_exec_pid;
                if !report.exec_response_rebound {
                    append_failure(
                        &mut failure,
                        "replacement KVM setup Exec journal did not bind to the fresh process",
                    );
                }
            }
            Ok(ProcessOperationJournalStatus::Prepared) => append_failure(
                &mut failure,
                "replacement KVM setup Exec journal remained prepared",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
    }

    if !first.response_delivered {
        match path_absent(&first.signal_marker).await {
            Ok(true) => {}
            Ok(false) => append_failure(
                &mut failure,
                "replacement KVM recovery dispatched an uncommitted SignalProcess before API retry",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    let calls_before_signal = driver.signal_process_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.signal_process(first.signal_process.clone()),
    )
    .await
    {
        Ok(Ok(())) => {
            report.operation_completed_after_reopen = true;
            report.generation_after_reopen = first.signal_process.process.container.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM SignalProcess did not retain the durable generation",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM SignalProcess failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM SignalProcess timed out"),
    }
    report.operation_replayed_without_driver_dispatch =
        driver.signal_process_calls() == calls_before_signal;
    match wait_for_exact_marker(
        &first.signal_marker,
        &qualification.signal_marker_contents,
        "replacement KVM SignalProcess",
    )
    .await
    {
        Ok(()) => report.replacement_signal_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match signal_process_journal_status(
        state_root,
        &first.signal_process.context.operation_id,
        &first.signal_process.process,
    )
    .await
    {
        Ok(SignalProcessJournalStatus::SucceededEmpty) => {
            report.replacement_response_matches_durable_record = true;
        }
        Ok(SignalProcessJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement KVM SignalProcess journal remained prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    if let Some(process) = replacement_exec.as_ref() {
        match durable_exec_process(state_root, &exact_process).await {
            Ok(durable) => {
                report.exec_response_rebound &= process == &durable;
                if !report.exec_response_rebound {
                    append_failure(
                        &mut failure,
                        "completed KVM SignalProcess did not retain the rebound Exec record",
                    );
                }
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    let calls_before_replay = driver.signal_process_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.signal_process(first.signal_process.clone()),
    )
    .await
    {
        Ok(Ok(())) if driver.signal_process_calls() == calls_before_replay => {}
        Ok(Ok(())) => append_failure(
            &mut failure,
            "later KVM SignalProcess replay reached the replacement driver",
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("later KVM SignalProcess replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "later KVM SignalProcess replay timed out"),
    }
    report.replacement_operation_dispatches = driver.signal_process_calls();
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM SignalProcess dispatch did not match the durable journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} SignalProcess dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if driver.start_calls() != 1 || driver.exec_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM recovery recorded {} Start and {} Exec dispatches",
                driver.start_calls(),
                driver.exec_calls()
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
            report.same_operation_id_reused = report.signal_process_request_identity_reused
                && identity.context.operation_id == first.signal_process.context.operation_id
                && identity.target == exact_process;
            if !report.signal_process_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM SignalProcess changed its operation, target, or signal identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let changed_signal = match Signal::new(9) {
        Ok(signal) => signal,
        Err(error) => {
            append_failure(
                &mut failure,
                format!("failed to construct changed SignalProcess signal: {error}"),
            );
            first.signal_process.signal
        }
    };
    let mut changed_host = first.signal_process.clone();
    changed_host.signal = changed_signal;
    let calls_before_changed_host = driver.signal_process_calls();
    match service.signal_process(changed_host).await {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && driver.signal_process_calls() == calls_before_changed_host =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong changed SignalProcess error: {error}"),
        ),
        Ok(()) => append_failure(
            &mut failure,
            "reopened KVM Host accepted changed SignalProcess",
        ),
    }
    let stale_container = match stale_target(&first.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            first.target.clone()
        }
    };
    let stale_process = ProcessTarget {
        container: stale_container.clone(),
        process_id: first.exec.process_id.clone(),
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        driver.guest_signal_process(AgentSignalProcessRequest {
            context: OperationContext::new(qualification.stale_guest_operation_id.clone()),
            target: stale_process.clone(),
            signal: first.signal_process.signal,
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest returned the wrong stale SignalProcess error: {error}"),
        ),
        Ok(Ok(())) => append_failure(
            &mut failure,
            "replacement KVM Guest accepted stale SignalProcess",
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement KVM Guest stale SignalProcess check timed out",
        ),
    }
    let calls_before_stale_host = driver.signal_process_calls();
    match service
        .signal_process(SignalProcessRequest {
            context: OperationContext::new(qualification.stale_host_operation_id.clone()),
            process: stale_process,
            signal: first.signal_process.signal,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.signal_process_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong stale SignalProcess error: {error}"),
        ),
        Ok(()) => append_failure(
            &mut failure,
            "reopened KVM Host accepted stale SignalProcess",
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
    match path_absent(&first.signal_marker).await {
        Ok(absent) => report.signal_marker_absent_after_cleanup = absent,
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
    if !report.marker_absent_after_cleanup
        || !report.exec_marker_absent_after_cleanup
        || !report.signal_marker_absent_after_cleanup
    {
        append_failure(
            &mut failure,
            "replacement KVM SignalProcess marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut failure,
            "replacement KVM SignalProcess owner left its runtime share",
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM SignalProcess owner identities were not distinct",
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
