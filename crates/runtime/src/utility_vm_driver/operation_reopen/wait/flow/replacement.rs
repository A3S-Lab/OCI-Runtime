use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentWaitRequest;
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, ErrorCode, Generation, ListRequest, OciRuntimeService,
    WaitRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{
    append_failure, init_exit_cache, path_absent, wait_for_replacement_marker, FirstOwnerOutcome,
};
use crate::driver::RuntimeDriver;
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    replacement_console: &Path,
    create: &CreateRequest,
    first: FirstOwnerOutcome,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let driver = Arc::new(QualificationKvmOperationDriver::with_wait_recovery(
        prepared,
        replacement_console.to_path_buf(),
        create.clone(),
        first.start.clone(),
        first.kill.clone(),
        first.marker.clone(),
    ));
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => service,
            Err(error) => {
                capture_recovery(&driver, report);
                report.replacement_vm = driver.shutdown().await;
                let cleanup = driver.cleanup(&first.target).await;
                report.marker_absent_after_cleanup =
                    path_absent(&first.marker).await.unwrap_or(false);
                return match cleanup {
                    Ok(()) => Err(format!("failed to reopen KVM Host service: {error}")),
                    Err(cleanup) => Err(format!(
                        "failed to reopen KVM Host service: {error}; {cleanup}"
                    )),
                };
            }
        };
    report.host_service_reopened = true;
    capture_recovery(&driver, report);

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
        || !report.replacement_rehydrated_stopped_record
    {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the complete stopped Guest tombstone",
        );
    }
    if report.replacement_created_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement KVM recovery did not retain its positive running PID",
        );
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            let exact = record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.state.id() == create.id.as_str()
                && first.target.generation == Some(record.generation)
                && record.config_digest == create.bundle.config_digest()
                && *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none();
            if !exact {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM Wait recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM Wait recovery retained {} records",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM Wait state: {error}"),
        ),
    }
    match init_exit_cache(state_root, &first.target).await {
        Ok(cache) => {
            let expected = first.response_delivered.then_some(&first.expected_exit);
            if cache.as_ref() != expected {
                append_failure(
                    &mut failure,
                    "reopened KVM Host did not preserve the exact init exit cache",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match wait_for_replacement_marker(&first.marker).await {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let wait_calls_before = driver.wait_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.wait(first.wait.clone())).await {
        Ok(Ok(status)) => {
            report.replacement_wait_exit_status = Some(status.clone());
            report.replacement_response_matches_expected_exit = status == first.expected_exit;
            report.operation_completed_after_reopen =
                report.replacement_response_matches_expected_exit;
            if !report.replacement_response_matches_expected_exit {
                append_failure(
                    &mut failure,
                    format!("replacement KVM Wait returned unexpected status {status:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Wait failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Wait timed out"),
    }
    report.operation_replayed_without_driver_dispatch = driver.wait_calls() == wait_calls_before;
    match init_exit_cache(state_root, &first.target).await {
        Ok(cache) => {
            report.init_exit_cached_after_reopen = cache.as_ref() == Some(&first.expected_exit);
            if !report.init_exit_cached_after_reopen {
                append_failure(
                    &mut failure,
                    "replacement KVM Wait did not persist the exact init exit cache",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_after_reopen = Some(record.generation);
            report.same_generation_reused = first.target.generation == Some(record.generation)
                && *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none();
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM Wait did not retain the exact stopped generation",
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!("replacement KVM Wait retained {} records", records.len()),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect state after replacement KVM Wait: {error}"),
        ),
    }

    let wait_calls_before_cache = driver.wait_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.wait(first.wait.clone())).await {
        Ok(Ok(status)) => {
            report.cached_wait_exit_status = Some(status.clone());
            report.cached_response_matches_expected_exit = status == first.expected_exit;
            if !report.cached_response_matches_expected_exit {
                append_failure(
                    &mut failure,
                    format!("cached KVM Wait returned unexpected status {status:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("cached KVM Wait replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "cached KVM Wait replay timed out"),
    }
    report.cached_wait_replayed_without_driver_dispatch =
        driver.wait_calls() == wait_calls_before_cache;
    report.replacement_operation_dispatches = driver.wait_calls();
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM Wait dispatch did not match the durable cache",
        );
    }
    let expected_dispatches = u32::from(!first.response_delivered);
    if report.replacement_operation_dispatches != expected_dispatches {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} Wait dispatches instead of {expected_dispatches}",
                report.replacement_operation_dispatches
            ),
        );
    }
    if !report.cached_wait_replayed_without_driver_dispatch {
        append_failure(
            &mut failure,
            "later KVM Wait did not replay from the durable terminal cache",
        );
    }
    match driver.wait_identity() {
        Ok(identity) if !first.response_delivered => {
            if identity != first.wait_identity {
                append_failure(
                    &mut failure,
                    "replacement KVM Wait changed the exact target or timeout",
                );
            }
        }
        Ok(_) => append_failure(
            &mut failure,
            "cache-backed replacement KVM Wait unexpectedly reached the driver",
        ),
        Err(_) if first.response_delivered => {}
        Err(reason) => append_failure(&mut failure, reason),
    }

    match driver.create_identity() {
        Ok(identity) => report.setup_create_identity_reused = identity == first.create_identity,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.start_identity() {
        Ok(identity) => report.setup_start_identity_reused = identity == first.start_identity,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.kill_identity() {
        Ok(identity) => report.setup_kill_identity_reused = identity == first.kill_identity,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if !report.setup_create_identity_reused
        || !report.setup_start_identity_reused
        || !report.setup_kill_identity_reused
    {
        append_failure(
            &mut failure,
            "replacement KVM Wait recovery changed a setup lifecycle identity",
        );
    }
    if driver.start_calls() != 1 || driver.kill_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM Wait recovery recorded {} Start and {} Kill dispatches",
                driver.start_calls(),
                driver.kill_calls()
            ),
        );
    }

    let stale_generation = match first.target.generation {
        Some(generation) => Generation(generation.0 + 1),
        None => {
            append_failure(&mut failure, "KVM Wait target had no exact generation");
            Generation(1)
        }
    };
    let stale_target = ContainerTarget::exact(create.id.clone(), stale_generation);
    match driver
        .guest_wait(AgentWaitRequest {
            target: stale_target.clone(),
            timeout_ms: first.wait.timeout_ms,
        })
        .await
    {
        Err(error) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("replacement KVM Guest returned the wrong stale Wait error: {error}"),
        ),
        Ok(status) => append_failure(
            &mut failure,
            format!("replacement KVM Guest accepted stale Wait with {status:?}"),
        ),
    }
    let wait_calls_before_stale_host = driver.wait_calls();
    match service
        .wait(WaitRequest {
            target: stale_target,
            timeout_ms: first.wait.timeout_ms,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.wait_calls() == wait_calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong stale Wait error: {error}"),
        ),
        Ok(status) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted stale Wait with {status:?}"),
        ),
    }

    let delete_calls_before = driver.delete_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.delete(first.delete.clone())).await {
        Ok(Ok(())) => report.stopped_only_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM stopped-only Delete failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Delete timed out"),
    }
    if driver.delete_calls() != delete_calls_before + 1 {
        append_failure(
            &mut failure,
            "replacement KVM cleanup did not dispatch exactly one Delete",
        );
    }
    match driver.delete_identity() {
        Ok(identity)
            if identity
                == (
                    first.delete.context.operation_id.clone(),
                    first.delete.target.clone(),
                    first.delete.mode,
                ) => {}
        Ok(_) => append_failure(
            &mut failure,
            "replacement KVM cleanup changed the stopped-only Delete identity",
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut failure,
                    format!("replacement KVM Delete retained {} records", records.len()),
                );
            }
        }
        Err(error) => append_failure(
            &mut failure,
            format!("failed to list after replacement KVM Delete: {error}"),
        ),
    }
    drop(service);
    report.replacement_vm = driver.shutdown().await;
    if let Err(reason) = driver.cleanup(&first.target).await {
        append_failure(&mut failure, reason);
    }
    match path_absent(&first.marker).await {
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
            "replacement KVM Wait marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(&mut failure, "replacement KVM owner left its runtime share");
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM Wait owner identities were not distinct",
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
    report.replacement_created_pid = driver.rehydrated_running_pid();
}
