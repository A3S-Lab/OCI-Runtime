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
    let driver = Arc::new(QualificationKvmOperationDriver::with_kill_recovery(
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
    if !report.replacement_rehydrated_created_record {
        append_failure(
            &mut failure,
            "replacement KVM driver did not rebuild the created process",
        );
    }
    if !report.replacement_rehydrated_running_record {
        append_failure(
            &mut failure,
            "replacement KVM driver did not restart the durable Kill process",
        );
    }
    if report.replacement_rehydrated_stopped_record != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM stopped rehydration did not match the durable Kill outcome",
        );
    }
    if report.replacement_created_pid.is_none() {
        append_failure(
            &mut failure,
            "replacement KVM recovery did not retain its positive running PID",
        );
    }

    let recovered = match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = records[0].clone();
            let expected_status = if first.response_delivered {
                ContainerState::Stopped
            } else {
                ContainerState::Running
            };
            let expected_pid = if first.response_delivered {
                record.state.pid().is_none()
            } else {
                *record.state.pid() == report.replacement_created_pid
            };
            let exact = record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.state.id() == create.id.as_str()
                && record.generation == first.target.generation.unwrap_or(record.generation)
                && *record.state.status() == expected_status
                && expected_pid;
            if !exact {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM recovery retained an inexact {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
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
                format!("failed to inspect recovered KVM Kill record: {error}"),
            );
            None
        }
    };

    if !first.response_delivered {
        let replayed_create =
            match timeout(QUALIFICATION_TIMEOUT, service.create(create.clone())).await {
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
                && *replayed_create.state.pid() == report.replacement_created_pid;
            if !report.setup_create_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement KVM Create replay did not bind to the fresh process identity",
                );
            }
        }

        match timeout(QUALIFICATION_TIMEOUT, service.start(first.start.clone())).await {
            Ok(Ok(record)) => {
                report.setup_start_response_rebound = *record.state.status()
                    == ContainerState::Running
                    && record.generation == first.target.generation.unwrap_or(record.generation)
                    && *record.state.pid() == report.replacement_created_pid;
                if !report.setup_start_response_rebound {
                    append_failure(
                        &mut failure,
                        "replacement KVM Start replay did not bind to the fresh process identity",
                    );
                }
            }
            Ok(Err(error)) => append_failure(
                &mut failure,
                format!("replacement KVM Start journal replay failed: {error}"),
            ),
            Err(_) => append_failure(
                &mut failure,
                "replacement KVM Start journal replay timed out",
            ),
        }
    }

    match wait_for_replacement_marker(&first.marker).await {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    let kill_calls_before = driver.kill_calls();
    match timeout(QUALIFICATION_TIMEOUT, service.kill(first.kill.clone())).await {
        Ok(Ok(record)) => {
            report.generation_after_reopen = Some(record.generation);
            report.operation_completed_after_reopen =
                *record.state.status() == ContainerState::Stopped && record.state.pid().is_none();
            report.replacement_response_matches_durable_record = service
                .list(ListRequest::default())
                .await
                .is_ok_and(|records| records.len() == 1 && records[0] == record);
            report.same_generation_reused =
                report.generation_before_reopen == Some(record.generation);
            if !report.operation_completed_after_reopen {
                append_failure(
                    &mut failure,
                    "replacement KVM Kill did not reach stopped state",
                );
            }
            if !report.replacement_response_matches_durable_record {
                append_failure(
                    &mut failure,
                    "replacement KVM Kill response differed from durable state",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM Kill changed the durable generation",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Kill failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Kill timed out"),
    }
    report.replacement_operation_dispatches = driver.kill_calls();
    report.operation_replayed_without_driver_dispatch =
        report.replacement_operation_dispatches == kill_calls_before;
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} Kill dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            "replacement KVM Kill dispatch did not match the durable journal",
        );
    }
    if driver.start_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} setup Start dispatches instead of one",
                driver.start_calls()
            ),
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
            report.setup_start_identity_reused = identity == first.start_identity
                && identity.0 == first.start.context.operation_id
                && identity.1 == first.start.target;
            if !report.setup_start_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup Start identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver.kill_identity() {
        Ok(identity) => {
            report.same_operation_id_reused = identity == first.kill_identity
                && identity.0 == first.kill.context.operation_id
                && identity.1 == first.kill.target
                && identity.2 == first.kill.signal
                && identity.3 == first.kill.all;
            if !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the Kill identity or target",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.delete(DeleteRequest {
            context: OperationContext::new(delete_operation_id.clone()),
            target: first.target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await
    {
        Ok(Ok(())) => report.stopped_only_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM stopped-only delete failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            "replacement KVM stopped-only delete timed out",
        ),
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
            "replacement KVM Kill marker remained after cleanup",
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
