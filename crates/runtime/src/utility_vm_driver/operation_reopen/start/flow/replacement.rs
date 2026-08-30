use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CreateRequest, DeleteMode, DeleteRequest, ListRequest, OciRuntimeService, OperationContext,
    OperationId,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{append_failure, path_absent, wait_for_replacement_marker, FirstOwnerOutcome};
use crate::driver::RuntimeDriver;
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    replacement_console: &Path,
    create: &CreateRequest,
    delete_operation_id: &OperationId,
    first: FirstOwnerOutcome,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let driver = Arc::new(QualificationKvmOperationDriver::with_start_recovery(
        prepared,
        replacement_console.to_path_buf(),
        create.clone(),
        first.start.clone(),
    ));
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => service,
            Err(error) => {
                report.replacement_recovery_calls = driver.recovery_calls();
                report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
                report.replacement_rehydrated_running_record = driver.rehydrated_running_record();
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
    report.replacement_recovery_calls = driver.recovery_calls();
    report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
    report.replacement_rehydrated_running_record = driver.rehydrated_running_record();

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
    if !report.replacement_rehydrated_created_record {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the created process",
        );
    }
    if report.replacement_rehydrated_running_record != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM running rehydration did not match the durable Start outcome",
        );
    }

    let recovered = match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = records[0].clone();
            let expected_status = if first.response_delivered {
                ContainerState::Running
            } else {
                ContainerState::Created
            };
            let exact = record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.state.id() == create.id.as_str()
                && record.generation == first.target.generation.unwrap_or(record.generation)
                && *record.state.status() == expected_status
                && record.state.pid().is_some_and(|pid| pid > 0);
            if !exact {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM recovery retained an inexact {} record",
                        record.state.status()
                    ),
                );
            }
            Some(record)
        }
        Ok(records) => {
            append_failure(
                &mut failure,
                format!(
                    "replacement KVM recovery retained {} records instead of one",
                    records.len()
                ),
            );
            None
        }
        Err(error) => {
            append_failure(
                &mut failure,
                format!("failed to inspect recovered KVM Start record: {error}"),
            );
            None
        }
    };

    let replayed_create = match timeout(QUALIFICATION_TIMEOUT, service.create(create.clone())).await
    {
        Ok(Ok(record)) => Some(record),
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement KVM Create journal replay failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(
                &mut failure,
                "replacement KVM Create journal replay timed out",
            );
            None
        }
    };
    if let (Some(recovered), Some(replayed_create)) = (&recovered, &replayed_create) {
        report.setup_create_response_rebound = *replayed_create.state.status()
            == ContainerState::Created
            && replayed_create.generation == recovered.generation
            && replayed_create.state.pid() == recovered.state.pid();
        if !report.setup_create_response_rebound {
            append_failure(
                &mut failure,
                "replacement KVM Create replay did not bind to the fresh process identity",
            );
        }
    }

    let start_calls_before = driver.start_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.start(first.start.clone())).await {
        Ok(Ok(record)) => {
            report.generation_after_reopen = Some(record.generation);
            report.replacement_created_pid = *record.state.pid();
            report.operation_completed_after_reopen =
                *record.state.status() == ContainerState::Running;
            report.replacement_response_matches_durable_record = service
                .list(ListRequest::default())
                .await
                .is_ok_and(|records| records.len() == 1 && records[0] == record);
            report.same_generation_reused =
                report.generation_before_reopen == Some(record.generation);
            if !report.operation_completed_after_reopen {
                append_failure(
                    &mut failure,
                    "replacement KVM Start did not reach running state",
                );
            }
            if !report.replacement_response_matches_durable_record {
                append_failure(
                    &mut failure,
                    "replacement KVM Start response differed from durable state",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM Start changed the durable generation",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Start failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Start timed out"),
    }
    report.replacement_operation_dispatches = driver.start_calls();
    report.operation_replayed_without_driver_dispatch =
        report.replacement_operation_dispatches == start_calls_before;
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} Start dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM Start dispatch did not match the completed durable journal",
        );
    }

    match driver.create_identity() {
        Ok(identity) => {
            report.setup_create_identity_reused = identity == first.create_identity
                && identity.0 == create.context.operation_id
                && identity.1.generation == report.generation_before_reopen;
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
            report.same_operation_id_reused = identity == first.start_identity
                && identity.0 == first.start.context.operation_id
                && identity.1 == first.start.target;
            if !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the Start identity or target",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    if report.operation_completed_after_reopen {
        match wait_for_replacement_marker(&first.marker).await {
            Ok(()) => report.replacement_workload_verified = true,
            Err(reason) => append_failure(&mut failure, reason),
        }
    } else {
        append_failure(
            &mut failure,
            "replacement KVM workload marker could not be verified before running state",
        );
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.delete(DeleteRequest {
            context: OperationContext::new(delete_operation_id.clone()),
            target: first.target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await
    {
        Ok(Ok(())) => report.force_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM force delete failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM force delete timed out"),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM delete retained {} durable records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut failure,
            format!("failed to list after replacement KVM delete: {error}"),
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
            "replacement KVM Start marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(&mut failure, "replacement KVM owner left its runtime share");
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM owner identities were not distinct",
        );
    }
    failure.map_or(Ok(()), Err)
}
