use std::sync::Arc;

use a3s_oci_agent_protocol::AgentReadOutputRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    DeleteMode, DeleteRequest, ErrorCode, ListRequest, OciRuntimeService, OperationContext,
    ProcessTarget, ReadOutputRequest,
};
use tokio::time::timeout;

use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::exec::support::{stale_target, wait_for_exact_marker};
use super::super::{append_failure, owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::record_recovery_evidence;
use super::{FirstOwnerEvidence, Qualification, QualificationHvfDriver};
use crate::agent_session::UtilityVmSession;
use crate::host_cleanup::MacosHostCleanupTracker;
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
                "failed to launch the replacement ReadOutput qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let driver = Arc::new(QualificationHvfDriver::with_exec_recovery(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
        qualification.start.clone(),
        Some(qualification.exec.clone()),
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
                "failed to reopen durable Host service around replacement ReadOutput VM: {error}"
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
        || report.replacement_rehydrated_signal_process
        || report.replacement_rehydrated_paused_record
        || report.replacement_rehydrated_resumed_record
        || report.replacement_rehydrated_update
    {
        append_failure(
            &mut failure,
            "replacement driver did not rebuild the exact live captured-output Exec",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement ReadOutput recovery did not retain positive init and Exec PIDs",
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
                "replacement ReadOutput recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered ReadOutput record: {error}"),
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
        "replacement ReadOutput init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match wait_for_exact_marker(
        &qualification.exec_marker,
        &qualification.exec_marker_contents,
        "replacement ReadOutput Exec",
    )
    .await
    {
        Ok(()) => report.replacement_exec_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let exec_calls_before_replay = driver.exec_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.exec(qualification.exec.clone()),
    )
    .await
    {
        Ok(Ok(process))
            if process.pid == report.replacement_exec_pid
                && process.target.container == qualification.start.target
                && process.target.process_id == qualification.exec.process_id
                && !process.terminal
                && driver.exec_calls() == exec_calls_before_replay =>
        {
            report.exec_response_rebound = true;
        }
        Ok(Ok(process)) => append_failure(
            &mut failure,
            format!("replacement Exec replay did not bind to the rebuilt process: {process:?}"),
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Exec replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement Exec replay timed out"),
    }

    let calls_before_read = driver.read_output_calls();
    let replacement_output = match timeout(
        QUALIFICATION_TIMEOUT,
        service.read_output(qualification.read_output.clone()),
    )
    .await
    {
        Ok(Ok(chunks)) => {
            report.replacement_output_verified = chunks == qualification.expected_output;
            report.output_response_rebound = report.replacement_output_verified
                && report.setup_create_response_rebound
                && report.setup_start_response_rebound
                && report.exec_response_rebound;
            report.operation_completed_after_reopen = report.replacement_output_verified;
            report.generation_after_reopen = qualification.start.target.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !report.replacement_output_verified {
                append_failure(
                    &mut failure,
                    "replacement ReadOutput did not return the nonce-bound captured output",
                );
            }
            if !report.output_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement ReadOutput was not bound to the rebuilt Exec process",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement ReadOutput changed the durable generation",
                );
            }
            Some(chunks)
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement ReadOutput failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement ReadOutput exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            );
            None
        }
    };
    report.replacement_output_chunks = replacement_output;
    report.operation_replayed_without_driver_dispatch =
        driver.read_output_calls() == calls_before_read;
    report.replacement_operation_dispatches = driver.read_output_calls();
    if report.operation_replayed_without_driver_dispatch {
        append_failure(
            &mut failure,
            "replacement ReadOutput did not reach the replacement driver",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recorded {} ReadOutput dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Exec", driver.exec_calls()),
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
    match driver.exec_identity() {
        Ok(identity) => {
            report.exec_request_identity_reused = identity == first.exec_identity;
            if !report.exec_request_identity_reused {
                append_failure(&mut failure, "replacement changed the setup Exec request");
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
                    "replacement changed the complete ReadOutput request",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let stale_container = match stale_target(&qualification.start.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            qualification.start.target.clone()
        }
    };
    let stale_process = ProcessTarget {
        container: stale_container,
        process_id: qualification.exec.process_id.clone(),
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().read_output(AgentReadOutputRequest {
            process: stale_process.clone(),
            after_sequence: qualification.read_output.after_sequence,
            max_bytes: qualification.read_output.max_bytes,
            wait_timeout_ms: qualification.read_output.wait_timeout_ms,
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong stale ReadOutput error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(&mut failure, "replacement Guest accepted stale ReadOutput"),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest stale ReadOutput check timed out",
        ),
    }
    let calls_before_stale_host = driver.read_output_calls();
    match service
        .read_output(ReadOutputRequest {
            process: stale_process,
            after_sequence: qualification.read_output.after_sequence,
            max_bytes: qualification.read_output.max_bytes,
            wait_timeout_ms: qualification.read_output.wait_timeout_ms,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.read_output_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong stale ReadOutput error: {error}"),
        ),
        Ok(_) => append_failure(&mut failure, "reopened Host accepted stale ReadOutput"),
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
