use std::sync::Arc;

use a3s_oci_agent_protocol::AgentExecRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    DeleteMode, DeleteRequest, ErrorCode, ExecRequest, ListRequest, OciRuntimeService,
    OperationContext, ProcessTarget, TerminalSize,
};
use tokio::time::timeout;

use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::{append_failure, owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{
    durable_exec_process, exact_process_target, exec_journal_status, record_recovery_evidence,
    stale_target, wait_for_exact_marker, ExecJournalStatus,
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
        Some(&qualification.system_image_manifest),
        &qualification.replacement_console,
    )
    .await
    {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            cleanup.apply(&mut bridge).await;
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the replacement Exec qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let recovery_exec = response_delivered.then(|| qualification.exec.clone());
    let driver = Arc::new(QualificationHvfDriver::with_exec_recovery(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
        qualification.start.clone(),
        recovery_exec,
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
                "failed to reopen durable Host service around the replacement Exec VM: {error}"
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
    {
        append_failure(
            &mut failure,
            "replacement driver did not rebuild the exact running init process",
        );
    }
    if report.replacement_rehydrated_exec_record != response_delivered {
        append_failure(
            &mut failure,
            "replacement live Exec rehydration did not match the durable journal outcome",
        );
    }
    if report.replacement_created_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement recovery did not retain a positive init PID",
        );
    }
    if response_delivered && report.replacement_exec_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement recovery did not retain a positive Exec PID",
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
                "replacement recovery retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered durable Exec record: {error}"),
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
        "replacement init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if !response_delivered {
        match super::super::super::path_exists(&qualification.exec_marker).await {
            Ok(false) => {}
            Ok(true) => append_failure(
                &mut failure,
                "replacement recovery dispatched an uncommitted Exec before API retry",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
    }

    let exact_process = exact_process_target(&qualification.exec);
    let calls_before = driver.exec_calls();
    let replacement_response = match timeout(
        QUALIFICATION_TIMEOUT,
        service.exec(qualification.exec.clone()),
    )
    .await
    {
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
                    format!("replacement Exec returned invalid process {process:?}"),
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement Exec did not retain the exact durable generation",
                );
            }
            Some(process)
        }
        Ok(Err(error)) => {
            append_failure(&mut failure, format!("replacement Exec failed: {error}"));
            None
        }
        Err(_) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement Exec exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            );
            None
        }
    };
    report.operation_replayed_without_driver_dispatch = driver.exec_calls() == calls_before;
    match wait_for_exact_marker(
        &qualification.exec_marker,
        &qualification.exec_marker_contents,
        "replacement Exec",
    )
    .await
    {
        Ok(()) => report.replacement_exec_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if let Some(response) = replacement_response.as_ref() {
        let journal = exec_journal_status(
            &qualification.state_root,
            &qualification.exec.context.operation_id,
            &exact_process,
        )
        .await;
        let durable = durable_exec_process(&qualification.state_root, &exact_process).await;
        match (journal, durable) {
            (Ok(ExecJournalStatus::Succeeded(journal)), Ok(durable)) => {
                report.replacement_response_matches_durable_record =
                    response == &journal && response == &durable;
                report.exec_response_rebound = report.replacement_response_matches_durable_record
                    && response.pid == report.replacement_exec_pid;
                if !report.exec_response_rebound {
                    append_failure(
                        &mut failure,
                        "replacement Exec journal did not bind to the fresh process identity",
                    );
                }
            }
            (Ok(ExecJournalStatus::Prepared), _) => append_failure(
                &mut failure,
                "replacement Exec left its durable journal prepared",
            ),
            (Err(reason), _) | (_, Err(reason)) => append_failure(&mut failure, reason),
        }

        let calls_before_replay = driver.exec_calls();
        match timeout(
            QUALIFICATION_TIMEOUT,
            service.exec(qualification.exec.clone()),
        )
        .await
        {
            Ok(Ok(replayed))
                if replayed == *response && driver.exec_calls() == calls_before_replay => {}
            Ok(Ok(replayed)) => append_failure(
                &mut failure,
                format!("later Exec replay changed process identity: {replayed:?}"),
            ),
            Ok(Err(error)) => append_failure(
                &mut failure,
                format!("later Exec journal replay failed: {error}"),
            ),
            Err(_) => append_failure(
                &mut failure,
                format!(
                    "later Exec replay exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            ),
        }
    }
    report.replacement_operation_dispatches = driver.exec_calls();
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut failure,
            "replacement Exec dispatch did not match the durable journal outcome",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recorded {} Exec dispatches instead of one",
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
                    "replacement recovery changed the setup Create identity",
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
                    "replacement recovery changed the setup Start identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.exec_identity() {
        Ok(identity) => {
            report.exec_request_identity_reused = identity == first.exec_identity;
            report.same_operation_id_reused = report.exec_request_identity_reused
                && identity.context.operation_id == qualification.exec.context.operation_id
                && identity.target == exact_process;
            if !report.exec_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement Exec changed its operation, process, terminal, or I/O identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let changed_size = TerminalSize {
        width: 100,
        height: 40,
    };
    let mut changed_host = qualification.exec.clone();
    changed_host.io.terminal_size = Some(changed_size);
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
            format!("reopened Host returned the wrong changed Exec error: {error}"),
        ),
        Ok(process) => append_failure(
            &mut failure,
            format!("reopened Host accepted changed Exec and returned {process:?}"),
        ),
    }
    let mut changed_guest_io = qualification.exec.io.clone();
    changed_guest_io.terminal_size = Some(changed_size);
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().exec(AgentExecRequest {
            context: qualification.exec.context.clone(),
            target: exact_process.clone(),
            process: qualification.exec.process.clone(),
            io: changed_guest_io,
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::Conflict => {
            report.guest_changed_request_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong changed Exec error: {error}"),
        ),
        Ok(Ok(process)) => append_failure(
            &mut failure,
            format!("replacement Guest accepted changed Exec and returned {process:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest changed Exec check timed out",
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
        session.client().exec(AgentExecRequest {
            context: OperationContext::new(qualification.stale_guest_operation_id.clone()),
            target: stale_process,
            process: qualification.exec.process.clone(),
            io: qualification.exec.io.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong stale Exec error: {error}"),
        ),
        Ok(Ok(process)) => append_failure(
            &mut failure,
            format!("replacement Guest accepted stale Exec and returned {process:?}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement Guest stale Exec check timed out"),
    }
    let calls_before_stale_host = driver.exec_calls();
    match service
        .exec(ExecRequest {
            context: OperationContext::new(qualification.stale_host_operation_id.clone()),
            container: stale_container,
            process_id: qualification.exec.process_id.clone(),
            process: qualification.exec.process.clone(),
            io: qualification.exec.io.clone(),
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
            format!("reopened Host returned the wrong stale Exec error: {error}"),
        ),
        Ok(process) => append_failure(
            &mut failure,
            format!("reopened Host accepted stale Exec and returned {process:?}"),
        ),
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
            format!("failed to inspect durable state after replacement delete: {error}"),
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
