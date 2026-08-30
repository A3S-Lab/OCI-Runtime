use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, KillRequest, ListRequest, OciRuntimeService, OperationContext,
    OperationId, Signal, StartRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::super::KILL_SIGNAL;
use super::support::{
    append_failure, path_absent, record_interruption, reset_marker, runtime_marker,
    wait_for_replacement_marker, FirstOwnerOutcome, KillIdentity,
};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::RuntimeDriver;
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::operation_journal_evidence::{
    container_operation_journal_status, ContainerOperationJournalStatus,
};
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    create: &CreateRequest,
    start_operation_id: &OperationId,
    kill_operation_id: &OperationId,
    stage: AgentTransportOperationStage,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<FirstOwnerOutcome, String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::Kill,
        AgentTransportFaultStage::from(stage),
    ));
    let guest_qualification = if stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                kill_operation_id.clone(),
                AgentOperation::Kill,
                stage,
            )
            .map_err(|error| format!("failed to construct Guest Kill qualification: {error}"))?,
        )
    } else {
        None
    };
    let session_qualification = match guest_qualification.as_ref() {
        Some(qualification) => UtilityVmSessionQualification::Guest(qualification.clone()),
        None => UtilityVmSessionQualification::Host(
            Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>
        ),
    };
    let driver = Arc::new(QualificationKvmOperationDriver::new(
        prepared,
        first_console.to_path_buf(),
        create.clone(),
        Some(session_qualification),
    ));
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => service,
            Err(error) => {
                report.first_vm = driver.shutdown().await;
                return Err(format!("failed to open first KVM Host service: {error}"));
            }
        };

    let created = match timeout(QUALIFICATION_TIMEOUT, service.create(create.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Created
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                format!(
                    "KVM Kill setup Create returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                format!("KVM Kill setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                "KVM Kill setup Create timed out".to_string(),
            )
            .await;
        }
    };
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let create_identity = match driver.create_identity() {
        Ok(identity) => identity,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    let mount_root = match driver.mount_root(&target).await {
        Ok(mount_root) => mount_root,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    let marker = match runtime_marker(&mount_root).await {
        Ok(marker) => marker,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    match path_absent(&marker).await {
        Ok(true) => {}
        Ok(false) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!(
                    "KVM Kill marker existed before setup Start: {}",
                    marker.display()
                ),
            )
            .await;
        }
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    }

    let start = StartRequest {
        context: OperationContext::new(start_operation_id.clone()),
        target: target.clone(),
    };
    let started = match timeout(QUALIFICATION_TIMEOUT, service.start(start.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!(
                    "KVM Kill setup Start returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM Kill setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Kill setup Start timed out".to_string(),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_replacement_marker(&marker).await {
        drop(service);
        return active_failure(
            &driver,
            &target,
            report,
            format!("KVM Kill setup workload failed: {reason}"),
        )
        .await;
    }
    report.first_created_pid = *started.state.pid();
    let start_identity = driver.start_identity();
    let signal = match Signal::new(KILL_SIGNAL) {
        Ok(signal) => signal,
        Err(error) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("failed to construct KVM Kill signal: {error}"),
            )
            .await;
        }
    };
    let kill = KillRequest {
        context: OperationContext::new(kill_operation_id.clone()),
        target: target.clone(),
        signal,
        all: true,
    };
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(QUALIFICATION_TIMEOUT, service.kill(kill.clone())).await {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, stage) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(record)) => append_failure(
            &mut failure,
            format!("first KVM Kill unexpectedly completed before owner replacement: {record:?}"),
        ),
        Err(_) => append_failure(&mut failure, "first KVM Kill timed out"),
    }

    let first_response = match container_operation_journal_status(
        state_root,
        &kill.context.operation_id,
        "kill",
        &kill.target,
    )
    .await
    {
        Ok(ContainerOperationJournalStatus::Prepared) if !response_delivered => None,
        Ok(ContainerOperationJournalStatus::Succeeded(response)) if response_delivered => {
            if *response.state.status() != ContainerState::Stopped || response.state.pid().is_some()
            {
                append_failure(
                    &mut failure,
                    format!(
                        "completed KVM Kill journal retained {} with PID {:?} instead of stopped",
                        response.state.status(),
                        response.state.pid()
                    ),
                );
            }
            Some(response)
        }
        Ok(ContainerOperationJournalStatus::Prepared) => {
            append_failure(
                &mut failure,
                "completed KVM Kill response left its Host journal prepared",
            );
            None
        }
        Ok(ContainerOperationJournalStatus::Succeeded(response)) => {
            append_failure(
                &mut failure,
                format!(
                    "KVM Kill Host journal committed before its response boundary: {response:?}"
                ),
            );
            None
        }
        Err(reason) => {
            append_failure(&mut failure, reason);
            None
        }
    };
    report.first_operation_dispatches = driver.kill_calls();
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_before_reopen = Some(record.generation);
            let exact_record = record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.state.id() == create.id.as_str()
                && record.generation == created.generation
                && record.config_digest == created.config_digest;
            report.durable_created_retained =
                exact_record && *record.state.status() == ContainerState::Created;
            report.durable_running_retained = exact_record
                && *record.state.status() == ContainerState::Running
                && record.state.pid() == started.state.pid();
            report.durable_stopped_retained = exact_record
                && *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none();
            report.first_response_matches_durable_record = first_response
                .as_ref()
                .is_some_and(|response| response.as_ref() == record);
            let retained_expected = if response_delivered {
                report.durable_stopped_retained && report.first_response_matches_durable_record
            } else {
                report.durable_running_retained && !report.first_response_matches_durable_record
            };
            if !retained_expected {
                append_failure(
                    &mut failure,
                    format!(
                        "interrupted KVM Kill retained {} instead of the exact durable {} record",
                        record.state.status(),
                        if response_delivered {
                            "stopped"
                        } else {
                            "running"
                        }
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM Kill retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect interrupted KVM Kill: {error}"),
        ),
    }
    let kill_identity = driver.kill_identity();
    drop(service);
    report.first_vm = driver.shutdown().await;
    match runtime_entries_clean(&mount_root).await {
        Ok(clean) => report.first_guest_runtime_clean = clean,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if let Some(qualification) = guest_qualification.as_ref() {
        match read_guest_qualification_evidence(first_console, qualification).await {
            Ok(evidence) => {
                report.negotiated_protocol = Some(evidence.protocol_version());
                report.injected_point = Some(evidence.injected_point());
                report.fault_crossings = evidence.fault_crossings();
                report.guest_evidence_operation_id = Some(evidence.operation_id().clone());
                report.guest_evidence_verified = evidence.matches_request(qualification)
                    && evidence.protocol_version() == AGENT_PROTOCOL_VERSION_MAX
                    && evidence.fault_crossings() == 1;
                if !report.guest_evidence_verified {
                    append_failure(
                        &mut failure,
                        "Guest Kill evidence did not match the exact KVM qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    match reset_marker(&marker).await {
        Ok(()) => report.marker_reset_before_replacement = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if !report.first_vm.is_success() {
        append_failure(
            &mut failure,
            report
                .first_vm
                .reason
                .clone()
                .unwrap_or_else(|| "first KVM VM cleanup evidence failed".to_string()),
        );
    }
    if !report.first_guest_runtime_clean {
        append_failure(
            &mut failure,
            "first KVM owner left Guest Agent runtime state",
        );
    }
    if driver.start_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "first KVM driver recorded {} setup Start dispatches instead of one",
                driver.start_calls()
            ),
        );
    }
    if report.first_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "first KVM driver recorded {} Kill dispatches instead of one",
                report.first_operation_dispatches
            ),
        );
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM Kill point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let start_identity = match start_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut failure, reason);
            (start.context.operation_id.clone(), start.target.clone())
        }
    };
    let kill_identity = match kill_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut failure, reason);
            fallback_kill_identity(&kill)
        }
    };
    if let Some(reason) = failure {
        return cleanup_failure(&driver, &target, reason).await;
    }
    drop(driver);
    Ok(FirstOwnerOutcome {
        target,
        mount_root,
        marker,
        create_identity,
        start_identity,
        kill_identity,
        start,
        kill,
        response_delivered,
    })
}

fn fallback_kill_identity(kill: &KillRequest) -> KillIdentity {
    (
        kill.context.operation_id.clone(),
        kill.target.clone(),
        kill.signal,
        kill.all,
    )
}

async fn setup_failure(
    driver: &QualificationKvmOperationDriver,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    report.first_vm = driver.shutdown().await;
    let cleanup = match driver.create_identity() {
        Ok((_, target)) => driver.cleanup(&target).await,
        Err(_) => Ok(()),
    };
    match cleanup {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}

async fn active_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    report.first_vm = driver.shutdown().await;
    cleanup_failure(driver, target, reason).await
}

async fn cleanup_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    match driver.cleanup(target).await {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}
