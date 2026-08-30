use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, KillRequest, ListRequest,
    OciRuntimeService, OperationContext, OperationId, Signal, StartRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::support::{
    append_failure, delete_journal_status, path_absent, record_interruption, reset_marker,
    runtime_marker, wait_for_replacement_marker, DeleteIdentity, FirstOwnerOutcome, KillIdentity,
};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::RuntimeDriver;
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::operation_journal_evidence::EmptyOperationJournalStatus;
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

const SETUP_KILL_SIGNAL: i32 = 9;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    create: &CreateRequest,
    start_operation_id: &OperationId,
    kill_operation_id: &OperationId,
    delete_operation_id: &OperationId,
    stage: AgentTransportOperationStage,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<FirstOwnerOutcome, String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::Delete,
        AgentTransportFaultStage::from(stage),
    ));
    let guest_qualification = if stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                delete_operation_id.clone(),
                AgentOperation::Delete,
                stage,
            )
            .map_err(|error| format!("failed to construct Guest Delete qualification: {error}"))?,
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
                    "KVM Delete setup Create returned invalid {} record with PID {:?}",
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
                format!("KVM Delete setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                "KVM Delete setup Create timed out".to_string(),
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
                    "KVM Delete marker existed before setup Start: {}",
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
                    "KVM Delete setup Start returned invalid {} record with PID {:?}",
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
                format!("KVM Delete setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Delete setup Start timed out".to_string(),
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
            format!("KVM Delete setup workload failed: {reason}"),
        )
        .await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(created.generation);
    let start_identity = driver.start_identity();
    let signal = match Signal::new(SETUP_KILL_SIGNAL) {
        Ok(signal) => signal,
        Err(error) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("failed to construct KVM Delete setup Kill signal: {error}"),
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
    match timeout(QUALIFICATION_TIMEOUT, service.kill(kill.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none() => {}
        Ok(Ok(record)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!(
                    "KVM Delete setup Kill returned {} with PID {:?}",
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
                format!("KVM Delete setup Kill failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM Delete setup Kill timed out".to_string(),
            )
            .await;
        }
    }
    let kill_identity = driver.kill_identity();
    let delete = DeleteRequest {
        context: OperationContext::new(delete_operation_id.clone()),
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(QUALIFICATION_TIMEOUT, service.delete(delete.clone())).await {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, stage) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(())) => append_failure(
            &mut failure,
            "first KVM Delete unexpectedly completed before owner replacement",
        ),
        Err(_) => append_failure(&mut failure, "first KVM Delete timed out"),
    }
    report.first_operation_dispatches = driver.delete_calls();
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    match service.list(ListRequest::default()).await {
        Ok(records) if response_delivered && records.is_empty() => {
            report.first_durable_records_empty = true;
        }
        Ok(records) if !response_delivered && records.len() == 1 => {
            let record = &records[0];
            let exact = record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.state.id() == create.id.as_str()
                && record.generation == created.generation
                && record.config_digest == created.config_digest
                && *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none();
            report.durable_stopped_retained = exact;
            if !exact {
                append_failure(
                    &mut failure,
                    format!(
                        "interrupted KVM Delete retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM Delete retained {} records; response_delivered={response_delivered}",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect interrupted KVM Delete: {error}"),
        ),
    }
    match delete_journal_status(state_root, &delete.context.operation_id, &delete.target).await {
        Ok(EmptyOperationJournalStatus::Prepared) if !response_delivered => {
            report.delete_journal_prepared_before_reopen = true;
        }
        Ok(EmptyOperationJournalStatus::SucceededEmpty) if response_delivered => {
            report.delete_journal_succeeded_empty_before_reopen = true;
        }
        Ok(status) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM Delete journal retained {status:?}; response_delivered={response_delivered}"
            ),
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    let delete_identity = driver.delete_identity();
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
                        "Guest Delete evidence did not match the exact KVM qualification",
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
    for (label, calls) in [
        ("Start", driver.start_calls()),
        ("Kill", driver.kill_calls()),
        ("Delete", driver.delete_calls()),
    ] {
        if calls != 1 {
            append_failure(
                &mut failure,
                format!("first KVM driver recorded {calls} {label} dispatches instead of one"),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM Delete point crossed {} times instead of once",
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
    let delete_identity = match delete_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut failure, reason);
            fallback_delete_identity(&delete)
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
        delete_identity,
        start,
        kill,
        delete,
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

fn fallback_delete_identity(delete: &DeleteRequest) -> DeleteIdentity {
    (
        delete.context.operation_id.clone(),
        delete.target.clone(),
        delete.mode,
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
