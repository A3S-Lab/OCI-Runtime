use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    DeleteMode, DeleteRequest, ErrorCode, ListRequest, OciRuntimeService, OperationContext,
};
use tokio::time::timeout;

use super::super::driver::QualificationKvmOperationDriver;
use super::super::exec::{stale_target, wait_for_exact_marker};
use super::super::mutation_support::{append_failure, empty_filesystem_response};
use super::super::workload_marker::path_absent;
use super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{
    capture_recovery, direct_effect_cleanup, direct_effect_query, dispatch_changed_host_mutation,
    dispatch_host_mutation, dispatch_stale_guest_mutation, dispatch_stale_host_mutation,
    driver_mutation_identity, effect_matches, mutation_calls, mutation_identity_operation_id,
    mutation_identity_target, mutation_journal_status, response_generation, response_matches,
    set_effect_absent, set_effect_verified, set_replacement_response_verified,
    set_request_identity_reused, set_response_replayed, MutationJournalStatus,
};
use super::{FirstOwnerOutcome, Mutation, Qualification};
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
    let label = qualification.mutation.label();
    let recovery_marker = first.response_delivered.then(|| {
        (
            first.init_marker.clone(),
            qualification.init_marker_contents.clone(),
        )
    });
    let driver = Arc::new(match &qualification.mutation {
        Mutation::File { request, .. } => QualificationKvmOperationDriver::with_file_recovery(
            prepared,
            replacement_console.to_path_buf(),
            qualification.create.clone(),
            first.start.clone(),
            first.response_delivered.then(|| request.clone()),
            recovery_marker,
        ),
        Mutation::Filesystem { request, .. } => {
            QualificationKvmOperationDriver::with_filesystem_recovery(
                prepared,
                replacement_console.to_path_buf(),
                qualification.create.clone(),
                first.start.clone(),
                first.response_delivered.then(|| request.clone()),
                recovery_marker,
            )
        }
    });
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => {
                report.host_service_reopened = true;
                capture_recovery(&driver, &qualification.mutation, report);
                service
            }
            Err(error) => {
                capture_recovery(&driver, &qualification.mutation, report);
                report.replacement_vm = driver.shutdown().await;
                let cleanup = driver.cleanup(&first.target).await;
                return match cleanup {
                    Ok(()) => Err(format!(
                        "failed to reopen KVM Host service for {label}: {error}"
                    )),
                    Err(cleanup) => Err(format!(
                        "failed to reopen KVM Host service for {label}: {error}; {cleanup}"
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
    let mutation_rehydrated = match &qualification.mutation {
        Mutation::File { .. } => report.replacement_rehydrated_file,
        Mutation::Filesystem { .. } => report.replacement_rehydrated_filesystem,
    };
    if !report.replacement_rehydrated_created_record
        || !report.replacement_rehydrated_running_record
        || report.replacement_rehydrated_stopped_record
        || report.replacement_rehydrated_exec_record
        || mutation_rehydrated != first.response_delivered
    {
        append_failure(
            &mut failure,
            format!("replacement KVM driver did not rebuild the exact running {label} state"),
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            format!("replacement KVM {label} recovery retained invalid PID evidence"),
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
                        "replacement KVM {label} recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM {label} recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM {label} record: {error}"),
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
        &format!("replacement KVM {label} init"),
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    if !first.response_delivered {
        match timeout(
            QUALIFICATION_TIMEOUT,
            direct_effect_query(&driver, &qualification.mutation, &first.target),
        )
        .await
        {
            Ok(Err(error)) if error.code == ErrorCode::NotFound => {}
            Ok(Err(error)) => append_failure(
                &mut failure,
                format!(
                    "fresh replacement KVM Guest returned the wrong pre-{label} error: {error}"
                ),
            ),
            Ok(Ok(response)) => append_failure(
                &mut failure,
                format!(
                    "fresh replacement KVM Guest retained an uncommitted {label} effect: {response:?}"
                ),
            ),
            Err(_) => append_failure(
                &mut failure,
                format!("fresh replacement KVM Guest pre-{label} check timed out"),
            ),
        }
    }

    let calls_before_mutation = mutation_calls(&driver, &qualification.mutation);
    let replacement_response = match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_host_mutation(&service, &qualification.mutation),
    )
    .await
    {
        Ok(Ok(response)) => {
            let response_valid =
                response_matches(&response, &qualification.mutation, &first.target);
            set_replacement_response_verified(report, &qualification.mutation, response_valid);
            report.operation_completed_after_reopen = response_valid;
            report.generation_after_reopen = response_generation(&response);
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !response_valid || !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    format!("replacement KVM {label} returned an invalid response: {response:?}"),
                );
            }
            Some(response)
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement KVM {label} failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(&mut failure, format!("replacement KVM {label} timed out"));
            None
        }
    };
    report.operation_replayed_without_driver_dispatch =
        mutation_calls(&driver, &qualification.mutation) == calls_before_mutation;
    match mutation_journal_status(state_root, &qualification.mutation, &first.target).await {
        Ok(MutationJournalStatus::Succeeded(journal)) => {
            report.replacement_response_matches_durable_record =
                replacement_response.as_ref() == Some(&journal);
            if !report.replacement_response_matches_durable_record {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM {label} response did not match its durable Host journal"
                    ),
                );
            }
        }
        Ok(MutationJournalStatus::Prepared) => append_failure(
            &mut failure,
            format!("replacement KVM {label} Host journal remained prepared"),
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    let replay_calls_before = mutation_calls(&driver, &qualification.mutation);
    match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_host_mutation(&service, &qualification.mutation),
    )
    .await
    {
        Ok(Ok(response)) => {
            let replayed = replacement_response.as_ref() == Some(&response)
                && mutation_calls(&driver, &qualification.mutation) == replay_calls_before;
            set_response_replayed(report, &qualification.mutation, replayed);
            if !replayed {
                append_failure(
                    &mut failure,
                    format!(
                        "durable KVM Host did not replay the exact {label} response without dispatch"
                    ),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} replay failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} replay timed out"),
        ),
    }
    report.replacement_operation_dispatches = mutation_calls(&driver, &qualification.mutation);
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            format!("replacement KVM {label} dispatch did not match the durable journal outcome"),
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} {label} dispatches instead of one",
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
    match driver_mutation_identity(&driver, &qualification.mutation) {
        Ok(identity) => {
            let identity_reused = identity == first.mutation_identity;
            set_request_identity_reused(report, &qualification.mutation, identity_reused);
            report.same_operation_id_reused = identity_reused
                && mutation_identity_operation_id(&identity)
                    == qualification.mutation.operation_id().ok()
                && mutation_identity_target(&identity) == &first.target;
            if !identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM {label} changed its operation, target, or payload identity"
                    ),
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_changed = mutation_calls(&driver, &qualification.mutation);
    match dispatch_changed_host_mutation(&service, &qualification.mutation).await {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && mutation_calls(&driver, &qualification.mutation) == calls_before_changed =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong changed {label} error: {error}"),
        ),
        Ok(response) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted changed {label} request: {response:?}"),
        ),
    }

    let stale_container = match stale_target(&first.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            first.target.clone()
        }
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_stale_guest_mutation(
            &driver,
            &qualification.mutation,
            stale_container.clone(),
            qualification.stale_guest_operation_id.clone(),
        ),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest returned the wrong stale {label} error: {error}"),
        ),
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest accepted stale {label}: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM Guest stale {label} check timed out"),
        ),
    }
    let stale_host_calls = mutation_calls(&driver, &qualification.mutation);
    match dispatch_stale_host_mutation(
        &service,
        &qualification.mutation,
        stale_container,
        qualification.stale_host_operation_id.clone(),
    )
    .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && mutation_calls(&driver, &qualification.mutation) == stale_host_calls =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong stale {label} error: {error}"),
        ),
        Ok(response) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted stale {label}: {response:?}"),
        ),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        direct_effect_query(&driver, &qualification.mutation, &first.target),
    )
    .await
    {
        Ok(Ok(response)) => {
            let verified = effect_matches(&response, &qualification.mutation, &first.target);
            set_effect_verified(report, &qualification.mutation, verified);
            if !verified {
                append_failure(
                    &mut failure,
                    format!("replacement KVM {label} effect was invalid: {response:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} effect query failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} effect query timed out"),
        ),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        direct_effect_cleanup(&driver, &qualification.mutation, &first.target),
    )
    .await
    {
        Ok(Ok(response)) if empty_filesystem_response(&response, &first.target) => {}
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup returned invalid metadata: {response:?}"),
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup timed out"),
        ),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        direct_effect_query(&driver, &qualification.mutation, &first.target),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            set_effect_absent(report, &qualification.mutation, true);
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup check returned the wrong error: {error}"),
        ),
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} effect remained after cleanup: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup check timed out"),
        ),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.delete(DeleteRequest {
            context: OperationContext::new(qualification.delete_operation_id.clone()),
            target: first.target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await
    {
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
            format!("replacement KVM {label} init marker remained after cleanup"),
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut failure,
            format!("replacement KVM {label} owner left its runtime share"),
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            format!("first and replacement KVM {label} owner identities were not distinct"),
        );
    }
    failure.map_or(Ok(()), Err)
}
