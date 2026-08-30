use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, ExecRequest, ListRequest, OciRuntimeService,
    OperationContext, ProcessTarget, StartRequest,
};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::{runtime_entries_clean, QUALIFICATION_TIMEOUT};
use super::super::Qualification;
use super::support::{
    active_failure, append_failure, cleanup_failure, durable_exec_process, exact_process_target,
    exec_journal_status, exec_marker, identity_or_expected, path_absent, reset_marker,
    runtime_marker, setup_failure, verify_first_dispatches, wait_for_exact_marker,
    ExecJournalStatus, FirstOwnerOutcome,
};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::{DriverExecRequest, DriverReadOutputRequest, RuntimeDriver};
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
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
        AgentOperation::ReadOutput,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let guest_qualification = if qualification.stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                qualification.read_output_operation_id.clone(),
                AgentOperation::ReadOutput,
                qualification.stage,
            )
            .map_err(|error| {
                format!("failed to construct Guest KVM ReadOutput qualification: {error}")
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
                && !record.is_paused()
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
                    "KVM ReadOutput setup Create returned invalid {} record with PID {:?}",
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
                format!("KVM ReadOutput setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                "KVM ReadOutput setup Create timed out".to_string(),
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
    let exec_marker = match exec_marker(&init_marker) {
        Ok(marker) => marker,
        Err(reason) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    };
    for (label, marker) in [("init", &init_marker), ("Exec", &exec_marker)] {
        match path_absent(marker).await {
            Ok(true) => {}
            Ok(false) => {
                drop(service);
                return active_failure(
                    &driver,
                    &target,
                    report,
                    format!(
                        "KVM ReadOutput {label} marker existed before setup Start: {}",
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
                && !record.is_paused()
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
                    "KVM ReadOutput setup Start returned invalid {} record with PID {:?}",
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
                format!("KVM ReadOutput setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM ReadOutput setup Start timed out".to_string(),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &init_marker,
        &qualification.init_marker_contents,
        "first-owner KVM ReadOutput init",
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
                format!("KVM ReadOutput setup Exec returned invalid process {process:?}"),
            )
            .await;
        }
        Ok(Err(error)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM ReadOutput setup Exec failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM ReadOutput setup Exec timed out".to_string(),
            )
            .await;
        }
    };
    report.first_exec_pid = first_exec.pid;
    if let Err(reason) = wait_for_exact_marker(
        &exec_marker,
        &qualification.exec_marker_contents,
        "first-owner KVM ReadOutput Exec",
    )
    .await
    {
        drop(service);
        return active_failure(&driver, &target, report, reason).await;
    }
    report.first_exec_marker_verified = true;
    match (
        exec_journal_status(state_root, &exec.context.operation_id, &exact_process).await,
        durable_exec_process(state_root, &exact_process).await,
    ) {
        (Ok(ExecJournalStatus::Succeeded(journal)), Ok(durable))
            if journal == first_exec && durable == first_exec =>
        {
            report.exec_journal_succeeded_before_reopen = true;
        }
        (Ok(ExecJournalStatus::Succeeded(_)), Ok(_)) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM ReadOutput setup Exec journal changed its durable process".to_string(),
            )
            .await;
        }
        (Ok(ExecJournalStatus::Prepared), _) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                "KVM ReadOutput setup Exec journal remained prepared".to_string(),
            )
            .await;
        }
        (Err(reason), _) | (_, Err(reason)) => {
            drop(service);
            return active_failure(&driver, &target, report, reason).await;
        }
    }

    let mut failure = super::first_query::run(
        &service,
        &driver,
        &target,
        qualification,
        faults.as_ref(),
        report,
    )
    .await;
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
                    "interrupted KVM ReadOutput did not retain the exact durable running record",
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM ReadOutput retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect durable state after KVM ReadOutput: {error}"),
        ),
    }
    let expected_driver_exec = DriverExecRequest {
        context: exec.context.clone(),
        target: ProcessTarget {
            container: target.clone(),
            process_id: exec.process_id.clone(),
        },
        process: exec.process.clone(),
        io: exec.io.clone(),
    };
    let expected_driver_read = DriverReadOutputRequest {
        target: exact_process,
        after_sequence: qualification.read_output.after_sequence,
        max_bytes: qualification.read_output.max_bytes,
        wait_timeout_ms: qualification.read_output.wait_timeout_ms,
    };
    let start_identity = driver.start_identity();
    let exec_identity = driver.exec_identity();
    let read_output_identity = driver.read_output_identity();

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
                        "Guest KVM ReadOutput evidence did not match the exact qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut failure, reason),
        }
    }
    match reset_marker(&init_marker).await {
        Ok(()) => report.marker_reset_before_replacement = true,
        Err(reason) => append_failure(&mut failure, reason),
    }
    match reset_marker(&exec_marker).await {
        Ok(()) => report.exec_marker_reset_before_replacement = true,
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
    verify_first_dispatches(&driver, report, &mut failure);
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM ReadOutput point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let start_identity = identity_or_expected(
        start_identity,
        &mut failure,
        (start.context.operation_id.clone(), start.target.clone()),
    );
    let exec_identity = identity_or_expected(exec_identity, &mut failure, expected_driver_exec);
    let read_output_identity =
        identity_or_expected(read_output_identity, &mut failure, expected_driver_read);
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
        create_identity,
        start_identity,
        exec_identity,
        read_output_identity,
        start,
        exec,
        delete,
    })
}
