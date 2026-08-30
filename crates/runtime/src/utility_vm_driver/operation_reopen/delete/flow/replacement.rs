use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{CreateRequest, ListRequest, OciRuntimeService};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{owner_identities_are_distinct, QUALIFICATION_TIMEOUT};
use super::support::{
    append_failure, delete_journal_status, path_absent, wait_for_replacement_marker,
    FirstOwnerOutcome,
};
use crate::driver::RuntimeDriver;
use crate::operation_journal_evidence::EmptyOperationJournalStatus;
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
    let driver = Arc::new(QualificationKvmOperationDriver::with_delete_recovery(
        prepared,
        replacement_console.to_path_buf(),
        create.clone(),
        first.start.clone(),
        first.kill.clone(),
        first.marker.clone(),
    ));
    if first.response_delivered {
        if let Err(error) = driver
            .launch_replacement_owner_without_workload(&first.target)
            .await
        {
            report.replacement_vm = driver.shutdown().await;
            let cleanup = driver.cleanup(&first.target).await;
            report.marker_absent_after_cleanup = path_absent(&first.marker).await.unwrap_or(false);
            return match cleanup {
                Ok(()) => Err(format!(
                    "failed to launch empty replacement KVM Delete owner: {error}"
                )),
                Err(cleanup) => Err(format!(
                    "failed to launch empty replacement KVM Delete owner: {error}; {cleanup}"
                )),
            };
        }
    }
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
    let recovery_required = !first.response_delivered;
    let expected_recoveries = u32::from(recovery_required);
    if report.replacement_recovery_calls != expected_recoveries {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recovered {} records instead of {expected_recoveries}",
                report.replacement_recovery_calls
            ),
        );
    }
    if report.replacement_rehydrated_created_record != recovery_required
        || report.replacement_rehydrated_running_record != recovery_required
        || report.replacement_rehydrated_stopped_record != recovery_required
    {
        append_failure(
            &mut failure,
            "replacement KVM rehydration did not match the durable Delete outcome",
        );
    }
    if report.replacement_created_pid.is_some() != recovery_required {
        append_failure(
            &mut failure,
            "replacement KVM running PID did not match the required Delete recovery path",
        );
    }

    match service.list(ListRequest::default()).await {
        Ok(records) if first.response_delivered && records.is_empty() => {}
        Ok(records) if !first.response_delivered && records.len() == 1 => {
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
                        "replacement KVM Delete recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM Delete recovery retained {} records; response_delivered={}",
                records.len(),
                first.response_delivered
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM Delete state: {error}"),
        ),
    }

    if first.response_delivered {
        match path_absent(&first.marker).await {
            Ok(true) => {}
            Ok(false) => append_failure(
                &mut failure,
                "completed KVM Delete unexpectedly rebuilt a replacement workload marker",
            ),
            Err(reason) => append_failure(&mut failure, reason),
        }
        if driver.create_identity().is_ok()
            || driver.start_identity().is_ok()
            || driver.kill_identity().is_ok()
            || driver.delete_identity().is_ok()
            || driver.start_calls() != 0
            || driver.kill_calls() != 0
            || driver.delete_calls() != 0
        {
            append_failure(
                &mut failure,
                "completed KVM Delete unexpectedly dispatched replacement workload operations",
            );
        }
    } else {
        match wait_for_replacement_marker(&first.marker).await {
            Ok(()) => report.replacement_workload_verified = true,
            Err(reason) => append_failure(&mut failure, reason),
        }
        match driver.create_identity() {
            Ok(identity) => {
                report.setup_create_identity_reused = identity == first.create_identity
                    && identity.0 == create.context.operation_id
                    && identity.1 == first.target;
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
        match driver.start_identity() {
            Ok(identity) => {
                report.setup_start_identity_reused = identity == first.start_identity
                    && identity.0 == first.start.context.operation_id
                    && identity.1 == first.start.target;
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
        match driver.kill_identity() {
            Ok(identity) => {
                report.setup_kill_identity_reused = identity == first.kill_identity
                    && identity.0 == first.kill.context.operation_id
                    && identity.1 == first.kill.target
                    && identity.2 == first.kill.signal
                    && identity.3 == first.kill.all;
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
        if !report.setup_create_identity_reused
            || !report.setup_start_identity_reused
            || !report.setup_kill_identity_reused
        {
            append_failure(
                &mut failure,
                "replacement KVM Delete recovery changed a setup lifecycle identity",
            );
        }
        if driver.start_calls() != 1 || driver.kill_calls() != 1 {
            append_failure(
                &mut failure,
                format!(
                    "replacement KVM Delete recovery recorded {} Start and {} Kill dispatches",
                    driver.start_calls(),
                    driver.kill_calls()
                ),
            );
        }
    }

    let delete_calls_before = driver.delete_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.delete(first.delete.clone())).await {
        Ok(Ok(())) => {
            report.operation_completed_after_reopen = true;
            report.generation_after_reopen = first.delete.target.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            report.stopped_only_delete_completed = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Delete failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Delete timed out"),
    }
    report.replacement_operation_dispatches = driver.delete_calls();
    report.operation_replayed_without_driver_dispatch =
        report.replacement_operation_dispatches == delete_calls_before;
    let expected_delete_dispatches = u32::from(!first.response_delivered);
    if report.replacement_operation_dispatches != expected_delete_dispatches {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} Delete dispatches instead of {expected_delete_dispatches}",
                report.replacement_operation_dispatches
            ),
        );
    }
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM Delete dispatch did not match the durable journal",
        );
    }
    if first.response_delivered {
        report.same_operation_id_reused = report.operation_completed_after_reopen
            && first.delete_identity
                == (
                    first.delete.context.operation_id.clone(),
                    first.delete.target.clone(),
                    first.delete.mode,
                )
            && report.replacement_operation_dispatches == 0;
    } else {
        match driver.delete_identity() {
            Ok(identity) => {
                report.same_operation_id_reused = identity == first.delete_identity
                    && identity.0 == first.delete.context.operation_id
                    && identity.1 == first.delete.target
                    && identity.2 == first.delete.mode;
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    if !report.same_operation_id_reused {
        append_failure(
            &mut failure,
            "replacement KVM path did not reuse the original Delete identity",
        );
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
            format!("failed to list after replacement KVM Delete: {error}"),
        ),
    }
    match delete_journal_status(
        state_root,
        &first.delete.context.operation_id,
        &first.delete.target,
    )
    .await
    {
        Ok(EmptyOperationJournalStatus::SucceededEmpty) => {
            report.delete_journal_succeeded_empty_after_reopen = true;
        }
        Ok(EmptyOperationJournalStatus::Prepared) => append_failure(
            &mut failure,
            "replacement KVM Delete left its durable journal prepared",
        ),
        Err(reason) => append_failure(&mut failure, reason),
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
            "replacement KVM Delete marker remained after cleanup",
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(&mut failure, "replacement KVM owner left its runtime share");
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            "first and replacement KVM Delete owner identities were not distinct",
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
