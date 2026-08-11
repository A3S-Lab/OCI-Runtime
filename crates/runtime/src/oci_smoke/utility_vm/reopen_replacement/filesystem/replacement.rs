use std::sync::Arc;

use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    DeleteMode, DeleteRequest, ErrorCode, FilesystemRequest, Generation, ListRequest,
    OciRuntimeService, OperationContext,
};
use tokio::time::timeout;

use super::super::exec::support::{stale_target, wait_for_exact_marker};
use super::super::{append_failure, owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{directory_response_matches, record_recovery_evidence};
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
        &qualification.replacement_console,
    )
    .await
    {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            cleanup.apply(&mut bridge).await;
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the replacement Filesystem qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let response_delivered = qualification.stage
        == a3s_oci_agent_protocol::AgentTransportOperationStage::GuestAfterResponseWrite;
    let recovery_filesystem = response_delivered.then(|| qualification.filesystem.clone());
    let recovery_marker = response_delivered.then(|| {
        (
            qualification.init_marker.clone(),
            qualification.init_marker_contents.clone(),
        )
    });
    let driver = Arc::new(QualificationHvfDriver::with_filesystem_recovery(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
        qualification.start.clone(),
        recovery_filesystem,
        recovery_marker,
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
                "failed to reopen durable Host service around replacement Filesystem VM: {error}"
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
        || report.replacement_rehydrated_exec_record
        || report.replacement_rehydrated_filesystem != response_delivered
    {
        append_failure(
            &mut failure,
            "replacement driver did not rebuild the exact running Filesystem state",
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            "replacement Filesystem recovery retained invalid init or Exec PID evidence",
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
                "replacement Filesystem recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered Filesystem record: {error}"),
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
        Err(_) => append_failure(&mut failure, "replacement Create replay timed out"),
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
        Err(_) => append_failure(&mut failure, "replacement Start replay timed out"),
    }
    match wait_for_exact_marker(
        &qualification.init_marker,
        &qualification.init_marker_contents,
        "replacement Filesystem init",
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let exact_stat = FilesystemRequest {
        target: qualification.start.target.clone(),
        ..qualification.stat.clone()
    };
    if !response_delivered {
        match timeout(
            QUALIFICATION_TIMEOUT,
            session.client().filesystem(exact_stat.clone()),
        )
        .await
        {
            Ok(Err(error)) if error.code == ErrorCode::NotFound => {}
            Ok(Err(error)) => append_failure(
                &mut failure,
                format!("fresh replacement Guest returned the wrong pre-mkdir error: {error}"),
            ),
            Ok(Ok(response)) => append_failure(
                &mut failure,
                format!("fresh replacement Guest retained an uncommitted directory: {response:?}"),
            ),
            Err(_) => append_failure(
                &mut failure,
                "fresh replacement Guest pre-mkdir check timed out",
            ),
        }
    }

    let calls_before_filesystem = driver.filesystem_calls();
    let replacement_response = match timeout(
        QUALIFICATION_TIMEOUT,
        service.filesystem(qualification.filesystem.clone()),
    )
    .await
    {
        Ok(Ok(response)) => {
            report.replacement_filesystem_response_verified = directory_response_matches(
                &response,
                &qualification.start.target,
                &qualification.filesystem.path,
            );
            report.operation_completed_after_reopen =
                report.replacement_filesystem_response_verified;
            report.generation_after_reopen =
                Some(response.target.generation.unwrap_or(Generation(u64::MAX)));
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !report.replacement_filesystem_response_verified || !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    format!("replacement Filesystem returned invalid metadata: {response:?}"),
                );
            }
            Some(response)
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement Filesystem failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(&mut failure, "replacement Filesystem timed out");
            None
        }
    };
    report.operation_replayed_without_driver_dispatch =
        driver.filesystem_calls() == calls_before_filesystem;
    let replay_calls_before = driver.filesystem_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.filesystem(qualification.filesystem.clone()),
    )
    .await
    {
        Ok(Ok(response)) => {
            report.filesystem_response_replayed = replacement_response.as_ref() == Some(&response)
                && driver.filesystem_calls() == replay_calls_before + 1;
            if !report.filesystem_response_replayed {
                append_failure(
                    &mut failure,
                    "replacement Guest did not replay the exact Filesystem response",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Filesystem replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement Filesystem replay timed out"),
    }
    report.replacement_operation_dispatches = driver.filesystem_calls();
    let expected_dispatches = if response_delivered { 3 } else { 2 };
    if report.operation_replayed_without_driver_dispatch
        || report.replacement_operation_dispatches != expected_dispatches
    {
        append_failure(
            &mut failure,
            format!(
                "replacement driver recorded {} Filesystem dispatches; expected {expected_dispatches}",
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
    match driver.filesystem_identity() {
        Ok(identity) => {
            report.filesystem_request_identity_reused = identity == first.filesystem_identity;
            report.same_operation_id_reused = report.filesystem_request_identity_reused
                && identity
                    .context
                    .as_ref()
                    .map(|context| &context.operation_id)
                    == qualification
                        .filesystem
                        .context
                        .as_ref()
                        .map(|context| &context.operation_id)
                && identity.target == qualification.start.target;
            if !report.filesystem_request_identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement Filesystem changed its operation, target, or path identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let mut changed_guest = qualification.filesystem.clone();
    changed_guest.target = qualification.start.target.clone();
    changed_guest.path = format!("{}-changed", qualification.filesystem.path);
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().filesystem(changed_guest.clone()),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::Conflict => {
            report.guest_changed_request_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong changed Filesystem error: {error}"),
        ),
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement Guest accepted changed Filesystem request: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest changed Filesystem check timed out",
        ),
    }
    let mut changed_host = changed_guest;
    changed_host.target = qualification.filesystem.target.clone();
    let changed_host_calls = driver.filesystem_calls();
    match service.filesystem(changed_host).await {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.filesystem_calls() == changed_host_calls + 1 =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong changed Filesystem error: {error}"),
        ),
        Ok(response) => append_failure(
            &mut failure,
            format!("reopened Host accepted changed Filesystem request: {response:?}"),
        ),
    }

    let stale_container = match stale_target(&qualification.start.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            qualification.start.target.clone()
        }
    };
    let stale_guest = FilesystemRequest {
        target: stale_container.clone(),
        context: Some(OperationContext::new(
            qualification.stale_guest_operation_id.clone(),
        )),
        ..qualification.filesystem.clone()
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().filesystem(stale_guest),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Guest returned the wrong stale Filesystem error: {error}"),
        ),
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement Guest accepted stale Filesystem request: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement Guest stale Filesystem check timed out",
        ),
    }
    let stale_host = FilesystemRequest {
        target: stale_container,
        context: Some(OperationContext::new(
            qualification.stale_host_operation_id.clone(),
        )),
        ..qualification.filesystem.clone()
    };
    let stale_host_calls = driver.filesystem_calls();
    match service.filesystem(stale_host).await {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.filesystem_calls() == stale_host_calls =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened Host returned the wrong stale Filesystem error: {error}"),
        ),
        Ok(response) => append_failure(
            &mut failure,
            format!("reopened Host accepted stale Filesystem request: {response:?}"),
        ),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().filesystem(exact_stat.clone()),
    )
    .await
    {
        Ok(Ok(response)) => {
            report.replacement_filesystem_effect_verified = directory_response_matches(
                &response,
                &qualification.start.target,
                &qualification.filesystem.path,
            );
            if !report.replacement_filesystem_effect_verified {
                append_failure(
                    &mut failure,
                    format!("replacement Filesystem Stat returned invalid metadata: {response:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Filesystem effect Stat failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement Filesystem effect Stat timed out"),
    }

    let exact_cleanup = FilesystemRequest {
        target: qualification.start.target.clone(),
        ..qualification.cleanup_filesystem.clone()
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().filesystem(exact_cleanup),
    )
    .await
    {
        Ok(Ok(response))
            if response.target == qualification.start.target
                && response.entry.is_none()
                && response.entries.is_empty() => {}
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement Filesystem cleanup returned invalid response: {response:?}"),
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Filesystem cleanup failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement Filesystem cleanup timed out"),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        session.client().filesystem(exact_stat),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.filesystem_effect_absent_after_cleanup = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement Filesystem cleanup check returned wrong error: {error}"),
        ),
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement Filesystem directory remained after cleanup: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement Filesystem cleanup check timed out",
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
        Err(_) => append_failure(&mut failure, "replacement force delete timed out"),
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
    report.replacement_guest_runtime_clean =
        super::super::super::runtime_entries(&qualification.vm_rootfs)
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
        append_failure(&mut failure, "replacement VM left guest runtime state");
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement VM owner identities were not distinct",
        );
    }
    failure.map_or(Ok(()), Err)
}
