use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CloseStdinRequest, ContainerTarget, DeleteMode, DeleteRequest, ExecRequest, ListRequest,
    OciRuntimeService, OperationContext, StartRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::exec::{exact_process_target, EXEC_MARKER_NAME};
use super::super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    append_failure, close_stdin_journal_status, durable_exec_process, path_absent, process_marker,
    record_interruption, reset_marker, runtime_marker, verify_first_close_marker,
    CloseStdinJournalStatus, FirstOwnerOutcome, CLOSE_MARKER_NAME,
};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::{DriverCloseStdinRequest, DriverExecRequest, RuntimeDriver};
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::operation_journal_evidence::ProcessOperationJournalStatus;
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

pub(super) async fn run(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<FirstOwnerOutcome, String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::CloseStdin,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let guest_qualification = if qualification.stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                qualification.close_operation_id.clone(),
                AgentOperation::CloseStdin,
                qualification.stage,
            )
            .map_err(|error| {
                format!("failed to construct Guest KVM CloseStdin qualification: {error}")
            })?,
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
        qualification.create.clone(),
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

    let created = match timeout(
        QUALIFICATION_TIMEOUT,
        service.create(qualification.create.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Created
                && record.state.id() == qualification.create.id.as_str()
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
                    "KVM CloseStdin setup Create returned invalid {} record with PID {:?}",
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
                format!("KVM CloseStdin setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                "KVM CloseStdin setup Create timed out".to_string(),
            )
            .await;
        }
    };
    let target = ContainerTarget::exact(qualification.create.id.clone(), created.generation);
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
    let init_marker = match runtime_marker(&mount_root).await {
        Ok(marker) => marker,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    let exec_marker = match process_marker(&init_marker, EXEC_MARKER_NAME, "Exec") {
        Ok(marker) => marker,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    let close_marker = match process_marker(&init_marker, CLOSE_MARKER_NAME, "CloseStdin") {
        Ok(marker) => marker,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    for (label, marker) in [
        ("init", &init_marker),
        ("Exec", &exec_marker),
        ("CloseStdin", &close_marker),
    ] {
        match path_absent(marker).await {
            Ok(true) => {}
            Ok(false) => {
                drop(service);
                return active_failure(
                    &driver,
                    &target,
                    report,
                    format!(
                        "KVM CloseStdin {label} marker existed before setup Start: {}",
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
    }

    let start = StartRequest {
        context: OperationContext::new(qualification.start_operation_id.clone()),
        target: target.clone(),
    };
    let started = match timeout(QUALIFICATION_TIMEOUT, service.start(start.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && record.generation == created.generation
                && record.state.id() == qualification.create.id.as_str()
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
                    "KVM CloseStdin setup Start returned invalid {} record with PID {:?}",
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
                format!("KVM CloseStdin setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM CloseStdin setup Start timed out".to_string(),
            )
            .await;
        }
    };
    if let Err(reason) = super::super::super::exec::wait_for_exact_marker(
        &init_marker,
        &qualification.init_marker_contents,
        "first-owner KVM CloseStdin init",
    )
    .await
    {
        drop(service);
        return active_failure(&driver, &target, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(created.generation);

    let exec = ExecRequest {
        context: OperationContext::new(qualification.exec_operation_id.clone()),
        container: target.clone(),
        process_id: qualification.process_id.clone(),
        process: qualification.process.clone(),
        io: qualification.io.clone(),
    };
    let exact_process = exact_process_target(&exec);
    let first_exec = match timeout(QUALIFICATION_TIMEOUT, service.exec(exec.clone())).await {
        Ok(Ok(process))
            if process.target == exact_process
                && process.pid.is_some_and(|pid| pid > 0)
                && !process.terminal =>
        {
            process
        }
        Ok(Ok(process)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM CloseStdin setup Exec returned invalid process {process:?}"),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM CloseStdin setup Exec failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM CloseStdin setup Exec timed out".to_string(),
            )
            .await;
        }
    };
    report.first_exec_pid = first_exec.pid;
    if let Err(reason) = super::super::super::exec::wait_for_exact_marker(
        &exec_marker,
        &qualification.exec_marker_contents,
        "first-owner KVM stdin Exec",
    )
    .await
    {
        drop(service);
        return active_failure(&driver, &target, report, reason).await;
    }
    report.first_exec_marker_verified = true;
    match (
        crate::operation_journal_evidence::process_operation_journal_status(
            state_root,
            &exec.context.operation_id,
            "exec",
            &exact_process,
        )
        .await,
        durable_exec_process(state_root, &exact_process).await,
    ) {
        (Ok(ProcessOperationJournalStatus::Succeeded(journal)), Ok(durable))
            if journal == first_exec && durable == first_exec =>
        {
            report.exec_journal_succeeded_before_reopen = true;
        }
        (Ok(ProcessOperationJournalStatus::Succeeded(_)), Ok(_)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM CloseStdin setup Exec journal changed its durable process".to_string(),
            )
            .await;
        }
        (Ok(ProcessOperationJournalStatus::Prepared), _) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM CloseStdin setup Exec journal remained prepared".to_string(),
            )
            .await;
        }
        (Err(reason), _) | (_, Err(reason)) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    }

    let close_stdin = CloseStdinRequest {
        context: OperationContext::new(qualification.close_operation_id.clone()),
        process: exact_process.clone(),
    };
    let response_delivered = qualification.stage
        == a3s_oci_agent_protocol::AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.close_stdin(close_stdin.clone()),
    )
    .await
    {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, qualification.stage) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(())) => append_failure(
            &mut failure,
            "first KVM CloseStdin unexpectedly completed before owner replacement",
        ),
        Err(_) => append_failure(&mut failure, "first KVM CloseStdin timed out"),
    }
    report.first_operation_dispatches = driver.close_stdin_calls();
    if qualification.stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    match verify_first_close_marker(
        &close_marker,
        &qualification.close_marker_contents,
        qualification.stage,
    )
    .await
    {
        Ok(()) => report.first_close_marker_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.durable_running_retained = record.state.id() == qualification.create.id.as_str()
                && record.driver == DriverKind::LibkrunKvm
                && record.isolation == IsolationClass::DedicatedVm
                && record.generation == created.generation
                && record.config_digest == created.config_digest
                && *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && *record.state.pid() == report.first_created_pid;
            if !report.durable_running_retained {
                append_failure(
                    &mut failure,
                    "interrupted KVM CloseStdin did not retain the exact durable running record",
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM CloseStdin retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect durable state after interrupted KVM CloseStdin: {error}"),
        ),
    }
    match close_stdin_journal_status(
        state_root,
        &close_stdin.context.operation_id,
        &close_stdin.process,
    )
    .await
    {
        Ok(CloseStdinJournalStatus::Prepared) => {
            report.close_stdin_journal_prepared_before_reopen = true;
            if response_delivered {
                append_failure(
                    &mut failure,
                    "delivered first KVM CloseStdin response left its journal prepared",
                );
            }
        }
        Ok(CloseStdinJournalStatus::SucceededEmpty) => {
            report.close_stdin_journal_succeeded_before_reopen = true;
            report.first_response_matches_durable_record = response_delivered;
            if !response_delivered {
                append_failure(
                    &mut failure,
                    "KVM CloseStdin journal committed before its response boundary",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    let expected_driver_exec = DriverExecRequest {
        context: exec.context.clone(),
        target: exact_process.clone(),
        process: exec.process.clone(),
        io: exec.io.clone(),
    };
    let expected_driver_close = DriverCloseStdinRequest {
        context: close_stdin.context.clone(),
        target: exact_process,
    };
    let start_identity = driver.start_identity();
    let exec_identity = driver.exec_identity();
    let close_stdin_identity = driver.close_stdin_identity();

    drop(service);
    report.first_vm = driver.shutdown().await;
    match runtime_entries_clean(&mount_root).await {
        Ok(clean) => report.first_guest_runtime_clean = clean,
        Err(reason) => append_failure(&mut failure, reason),
    }
    if let Some(request) = guest_qualification.as_ref() {
        match read_guest_qualification_evidence(first_console, request).await {
            Ok(evidence) => {
                report.negotiated_protocol = Some(evidence.protocol_version());
                report.injected_point = Some(evidence.injected_point());
                report.fault_crossings = evidence.fault_crossings();
                report.guest_evidence_operation_id = Some(evidence.operation_id().clone());
                report.guest_evidence_verified = evidence.matches_request(request)
                    && evidence.protocol_version() == AGENT_PROTOCOL_VERSION_MAX
                    && evidence.fault_crossings() == 1;
                if !report.guest_evidence_verified {
                    append_failure(
                        &mut failure,
                        "Guest KVM CloseStdin evidence did not match the exact qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    for (marker, field) in [
        (&init_marker, &mut report.marker_reset_before_replacement),
        (
            &exec_marker,
            &mut report.exec_marker_reset_before_replacement,
        ),
        (
            &close_marker,
            &mut report.close_marker_reset_before_replacement,
        ),
    ] {
        match reset_marker(marker).await {
            Ok(()) => *field = true,
            Err(reason) => append_failure(&mut failure, reason),
        }
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
            "first KVM CloseStdin owner left Guest Agent runtime state",
        );
    }
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Exec", driver.exec_calls()),
        ("CloseStdin", report.first_operation_dispatches),
    ] {
        if actual != 1 {
            append_failure(
                &mut failure,
                format!("first KVM driver recorded {actual} {label} dispatches instead of one"),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM CloseStdin point crossed {} times instead of once",
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
    let exec_identity = match exec_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut failure, reason);
            expected_driver_exec
        }
    };
    let close_stdin_identity = match close_stdin_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut failure, reason);
            expected_driver_close
        }
    };
    let delete = DeleteRequest {
        context: OperationContext::new(qualification.delete_operation_id.clone()),
        target: target.clone(),
        mode: DeleteMode::Force,
    };
    if let Some(reason) = failure {
        return cleanup_failure(&driver, &target, reason).await;
    }
    drop(driver);
    Ok(FirstOwnerOutcome {
        target,
        mount_root,
        init_marker,
        exec_marker,
        close_marker,
        create_identity,
        start_identity,
        exec_identity,
        close_stdin_identity,
        start,
        exec,
        close_stdin,
        delete,
        response_delivered,
    })
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
