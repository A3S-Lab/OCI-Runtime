use std::sync::Arc;

use a3s_oci_agent_protocol::AgentCloseStdinRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CloseStdinRequest, DeleteMode, DeleteRequest, ErrorCode, ListRequest, OciRuntimeService,
    OperationContext, ProcessTarget,
};
use tokio::time::timeout;

use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::exec::support::{
    durable_exec_process, exact_process_target, exec_journal_status, stale_target,
    wait_for_exact_marker, ExecJournalStatus,
};
use super::super::{append_failure, owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{
    close_stdin_journal_status, record_recovery_evidence, CloseStdinJournalStatus,
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
        &qualification.replacement_console,
    )
    .await
    {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            cleanup.apply(&mut bridge).await;
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the replacement CloseStdin qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let recovery_close_stdin = response_delivered.then(|| qualification.close_stdin.clone());
    let recovery_write_ready_marker = response_delivered.then(|| {
        (
            qualification.exec_marker.clone(),
            qualification.exec_marker_contents.clone(),
        )
    });
    let driver = Arc::new(QualificationHvfDriver::with_close_stdin_recovery(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
        qualification.start.clone(),
        qualification.exec.clone(),
        recovery_close_stdin,
        recovery_write_ready_marker,
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
                "failed to reopen durable Host service around replacement CloseStdin VM: {error}"
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
        || !report.replacement_rehydrated_exec_record
    {
        append_failure(
            &mut failure,
            "replacement driver did not rebuild the exact running init and Exec processes",
        );
    }
    if report.replacement_rehydrated_close_stdin != response_delivered {
        append_failure(
            &mut failure,
            "replacement recovery stdin replay did not match the durable journal outcome",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement recovery did not retain positive init and Exec PIDs",
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
                "replacement CloseStdin recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered CloseStdin record: {error}"),
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
        "replacement CloseStdin init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match wait_for_exact_marker(
        &qualification.exec_marker,
        &qualification.exec_marker_contents,
        "replacement stdin Exec",
    )
    .await
    {
        Ok(()) => report.replacement_exec_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let exact_process = exact_process_target(&qualification.exec);
    let exec_calls_before_replay = driver.exec_calls();
    let replacement_exec = match timeout(
        QUALIFICATION_TIMEOUT,
        service.exec(qualification.exec.clone()),
    )
    .await
    {
        Ok(Ok(process))
            if process.target == exact_process
                && process.pid.is_some_and(|pid| pid > 0)
                && !process.terminal
                && driver.exec_calls() == exec_calls_before_replay =>
        {
            report.replacement_exec_pid = process.pid;
            Some(process)
        }
        Ok(Ok(process)) => {
            append_failure(
                &mut failure,
                format!("replacement setup Exec replay returned invalid process {process:?}"),
            );
            None
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement setup Exec replay failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(&mut failure, "replacement setup Exec replay timed out");
            None
        }
    };
    if let Some(process) = replacement_exec.as_ref() {
        match exec_journal_status(
            &qualification.state_root,
            &qualification.exec.context.operation_id,
            &exact_process,
        )
        .await
        {
            Ok(ExecJournalStatus::Succeeded(journal)) => {
                report.exec_response_rebound =
                    process == &journal && process.pid == report.replacement_exec_pid;
                if !report.exec_response_rebound {
                    append_failure(
                        &mut failure,
                        "replacement setup Exec journal did not bind to the fresh process",
                    );
                }
            }
            Ok(ExecJournalStatus::Prepared) => append_failure(
                &mut failure,
                "replacement setup Exec journal remained prepared",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
    }

    if !response_delivered {
        match super::super::super::path_exists(&qualification.close_marker).await {
            Ok(false) => {}
            Ok(true) => append_failure(
                &mut failure,
                "replacement recovery dispatched an uncommitted CloseStdin before API retry",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    let calls_before_write = driver.close_stdin_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.close_stdin(qualification.close_stdin.clone()),
    )
    .await
    {
        Ok(Ok(())) => {
            report.operation_completed_after_reopen = true;
            report.generation_after_reopen = qualification.close_stdin.process.container.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement CloseStdin did not retain the durable generation",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement CloseStdin failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!(
                "replacement CloseStdin exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    report.operation_replayed_without_driver_dispatch =
        driver.close_stdin_calls() == calls_before_write;
    match wait_for_exact_marker(
        &qualification.close_marker,
        &qualification.close_marker_contents,
        "replacement CloseStdin",
    )
    .await
    {
        Ok(()) => report.replacement_close_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match close_stdin_journal_status(
        &qualification.state_root,
        &qualification.close_stdin.context.operation_id,
        &qualification.close_stdin.process,
    )
    .await
    {
        Ok(CloseStdinJournalStatus::SucceededEmpty) => {
            report.replacement_response_matches_durable_record = true;
        }
        Ok(CloseStdinJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement CloseStdin journal remained prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    if let Some(process) = replacement_exec.as_ref() {
        match durable_exec_process(&qualification.state_root, &exact_process).await {
            Ok(durable) => {
                report.exec_response_rebound &= process == &durable;
                if !report.exec_response_rebound {
                    append_failure(
                        &mut failure,
                        "completed CloseStdin did not release the rebound Exec record",
                    );
                }
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    let calls_before_replay = driver.close_stdin_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.close_stdin(qualification.close_stdin.clone()),
    )
    .await
    {
        Ok(Ok(())) if driver.close_stdin_calls() == calls_before_replay => {}
        Ok(Ok(())) => append_failure(
            &mut failure,
            "later CloseStdin replay reached the replacement driver",
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("later CloseStdin replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "later CloseStdin replay timed out"),
    }
    report.replacement_operation_dispatches = driver.close_stdin_calls();
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut failure,
            "replacement CloseStdin dispatch did not match the journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recorded {} CloseStdin dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if driver.start_calls() != 1 || driver.exec_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement recovery recorded {} Start and {} Exec dispatches",
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
    match driver.exec_identity() {
        Ok(identity) => {
            report.exec_request_identity_reused = identity == first.exec_identity;
            if !report.exec_request_identity_reused {
                append_failure(&mut failure, "replacement changed the setup Exec identity");
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.close_stdin_identity() {
        Ok(identity) => {
            report.close_stdin_request_identity_reused = identity == first.close_stdin_identity;
            report.same_operation_id_reused = report.close_stdin_request_identity_reused
                && identity.context.operation_id == qualification.close_stdin.context.operation_id
                && identity.target == exact_process;
            if !report.close_stdin_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement CloseStdin changed its operation or target identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let mut changed_host = qualification.close_stdin.clone();
    changed_host.process.process_id = qualification.changed_process_id.clone();
    let calls_before_changed_host = driver.close_stdin_calls();
    match service.close_stdin(changed_host).await {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && driver.close_stdin_calls() == calls_before_changed_host =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong changed CloseStdin error: {error}"),
        ),
        Ok(()) => append_failure(&mut failure, "reopened Host accepted changed CloseStdin"),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().close_stdin(AgentCloseStdinRequest {
            context: Some(qualification.close_stdin.context.clone()),
            process: ProcessTarget {
                container: exact_process.container.clone(),
                process_id: qualification.changed_process_id.clone(),
            },
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::Conflict => {
            report.guest_changed_request_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong changed CloseStdin error: {error}"),
        ),
        Ok(Ok(())) => append_failure(
            &mut failure,
            "replacement Guest accepted changed CloseStdin",
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest changed CloseStdin check timed out",
        ),
    }

    let stale_container = match stale_target(&qualification.start.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            qualification.start.target.clone()
        }
    };
    let stale_process = ProcessTarget {
        container: stale_container.clone(),
        process_id: qualification.exec.process_id.clone(),
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().close_stdin(AgentCloseStdinRequest {
            context: Some(OperationContext::new(
                qualification.stale_guest_operation_id.clone(),
            )),
            process: stale_process.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong stale CloseStdin error: {error}"),
        ),
        Ok(Ok(())) => append_failure(&mut failure, "replacement Guest accepted stale CloseStdin"),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest stale CloseStdin check timed out",
        ),
    }
    let calls_before_stale_host = driver.close_stdin_calls();
    match service
        .close_stdin(CloseStdinRequest {
            context: OperationContext::new(qualification.stale_host_operation_id.clone()),
            process: stale_process,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.close_stdin_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong stale CloseStdin error: {error}"),
        ),
        Ok(()) => append_failure(&mut failure, "reopened Host accepted stale CloseStdin"),
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
