use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentExecRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ErrorCode, ExecRequest, ListRequest, OciRuntimeService, OperationContext, ProcessTarget,
    TerminalSize,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    append_failure, durable_exec_process, exact_process_target, exec_journal_status, path_absent,
    stale_target, wait_for_exact_marker, ExecJournalStatus, FirstOwnerOutcome,
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
    let recovery_exec = first.response_delivered.then(|| first.exec.clone());
    let driver = Arc::new(QualificationKvmOperationDriver::with_exec_recovery(
        prepared,
        replacement_console.to_path_buf(),
        qualification.create.clone(),
        first.start.clone(),
        recovery_exec,
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
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the exact running init process",
        );
    }
    if report.replacement_rehydrated_exec_record != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM live Exec rehydration did not match the durable journal outcome",
        );
    }
    if report.replacement_created_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement KVM recovery did not retain a positive init PID",
        );
    }
    if first.response_delivered && report.replacement_exec_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement KVM recovery did not retain a positive Exec PID",
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
                        "replacement KVM recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM recovery retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered durable KVM Exec record: {error}"),
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
        "replacement KVM init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if !first.response_delivered {
        match path_absent(&first.exec_marker).await {
            Ok(true) => {}
            Ok(false) => append_failure(
                &mut failure,
                "replacement KVM recovery dispatched an uncommitted Exec before API retry",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
    }

    let exact_process = exact_process_target(&first.exec);
    let calls_before = driver.exec_calls();
    let replacement_response =
        match timeout(QUALIFICATION_TIMEOUT, service.exec(first.exec.clone())).await {
            Ok(Ok(process)) => {
                report.generation_after_reopen = process.target.container.generation;
                report.replacement_exec_pid = process.pid;
                report.operation_completed_after_reopen = process.target == exact_process
                    && process.pid.is_some_and(|pid| pid > 0)
                    && process.terminal;
                report.same_generation_reused =
                    report.generation_before_reopen == report.generation_after_reopen;
                if !report.operation_completed_after_reopen {
                    append_failure(
                        &mut failure,
                        format!("replacement KVM Exec returned invalid process {process:?}"),
                    );
                }
                if !report.same_generation_reused {
                    append_failure(
                        &mut failure,
                        "replacement KVM Exec did not retain the exact durable generation",
                    );
                }
                Some(process)
            }
            Ok(Err(error)) => {
                append_failure(
                    &mut failure,
                    format!("replacement KVM Exec failed: {error}"),
                );
                None
            }
            Err(_) => {
                append_failure(&mut failure, "replacement KVM Exec timed out");
                None
            }
        };
    report.operation_replayed_without_driver_dispatch = driver.exec_calls() == calls_before;
    match wait_for_exact_marker(
        &first.exec_marker,
        &qualification.exec_marker_contents,
        "replacement KVM Exec",
    )
    .await
    {
        Ok(()) => report.replacement_exec_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if let Some(response) = replacement_response.as_ref() {
        let journal =
            exec_journal_status(state_root, &first.exec.context.operation_id, &exact_process).await;
        let durable = durable_exec_process(state_root, &exact_process).await;
        match (journal, durable) {
            (Ok(ExecJournalStatus::Succeeded(journal)), Ok(durable)) => {
                report.replacement_response_matches_durable_record =
                    response == &journal && response == &durable;
                report.exec_response_rebound = report.replacement_response_matches_durable_record
                    && response.pid == report.replacement_exec_pid;
                if !report.exec_response_rebound {
                    append_failure(
                        &mut failure,
                        "replacement KVM Exec journal did not bind to the fresh process identity",
                    );
                }
            }
            (Ok(ExecJournalStatus::Prepared), _) => append_failure(
                &mut failure,
                "replacement KVM Exec left its durable journal prepared",
            ),
            (Err(reason), _) | (_, Err(reason)) => append_failure(&mut failure, reason),
        }

        let calls_before_replay = driver.exec_calls();
        match timeout(QUALIFICATION_TIMEOUT, service.exec(first.exec.clone())).await {
            Ok(Ok(replayed))
                if replayed == *response && driver.exec_calls() == calls_before_replay => {}
            Ok(Ok(replayed)) => append_failure(
                &mut failure,
                format!("later KVM Exec replay changed process identity: {replayed:?}"),
            ),
            Ok(Err(error)) => append_failure(
                &mut failure,
                format!("later KVM Exec journal replay failed: {error}"),
            ),
            Err(_) => append_failure(&mut failure, "later KVM Exec replay timed out"),
        }
    }
    report.replacement_operation_dispatches = driver.exec_calls();
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM Exec dispatch did not match the durable journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} Exec dispatches instead of one",
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
    match driver.exec_identity() {
        Ok(identity) => {
            report.exec_request_identity_reused = identity == first.exec_identity;
            report.same_operation_id_reused = report.exec_request_identity_reused
                && identity.context.operation_id == first.exec.context.operation_id
                && identity.target == exact_process;
            if !report.exec_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM Exec changed its operation, process, terminal, or I/O identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let mut changed_host = first.exec.clone();
    changed_host.io.terminal_size = Some(TerminalSize {
        width: 100,
        height: 40,
    });
    let calls_before_changed_host = driver.exec_calls();
    match service.exec(changed_host).await {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && driver.exec_calls() == calls_before_changed_host =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong changed Exec error: {error}"),
        ),
        Ok(process) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted changed Exec and returned {process:?}"),
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
        driver.guest_exec(AgentExecRequest {
            context: OperationContext::new(qualification.stale_guest_operation_id.clone()),
            target: stale_process,
            process: first.exec.process.clone(),
            io: first.exec.io.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest returned the wrong stale Exec error: {error}"),
        ),
        Ok(Ok(process)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest accepted stale Exec and returned {process:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement KVM Guest stale Exec check timed out",
        ),
    }
    let calls_before_stale_host = driver.exec_calls();
    match service
        .exec(ExecRequest {
            context: OperationContext::new(qualification.stale_host_operation_id.clone()),
            container: stale_container,
            process_id: first.exec.process_id.clone(),
            process: first.exec.process.clone(),
            io: first.exec.io.clone(),
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.exec_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong stale Exec error: {error}"),
        ),
        Ok(process) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted stale Exec and returned {process:?}"),
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
            "replacement KVM Exec marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(&mut failure, "replacement KVM owner left its runtime share");
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM Exec owner identities were not distinct",
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
    report.replacement_created_pid = driver.rehydrated_running_pid();
    report.replacement_exec_pid = driver
        .rehydrated_exec_pid()
        .and_then(|pid| u32::try_from(pid).ok());
}
