use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ListRequest, OciRuntimeService, StateRequest};
use tokio::time::timeout;

use super::super::super::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use super::super::super::{runtime_entries, GUEST_RUNTIME_PREFIX};
use super::super::exec::support::{
    durable_exec_process, exact_process_target, exec_journal_status, reset_marker,
    shutdown_setup_failure, wait_for_exact_marker, ExecJournalStatus,
};
use super::super::{append_failure, QUALIFICATION_TIMEOUT};
use super::support::{
    identity_or_expected, process_exit_cache, record_interruption, signal_process_journal_status,
    SignalProcessJournalStatus,
};
use super::{FirstOwnerEvidence, Qualification, QualificationHvfDriver};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::{
    DriverExecRequest, DriverSignalProcessRequest, OciVmOperationReopenReplacementReport,
    RuntimeDriver,
};

pub(super) async fn run(
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<FirstOwnerEvidence, String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::WaitProcess,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let cleanup = MacosHostCleanupTracker::capture();
    let session_result = match qualification.guest_qualification.as_ref() {
        Some(request) => {
            crate::agent_session::UtilityVmSession::connect_with_guest_qualification(
                &qualification.shim,
                &qualification.vm_rootfs,
                &qualification.first_console,
                request,
            )
            .await
        }
        None => {
            crate::agent_session::UtilityVmSession::connect_with_host_fault_injector(
                &qualification.shim,
                &qualification.vm_rootfs,
                &qualification.first_console,
                Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>,
            )
            .await
        }
    };
    let session = match session_result {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            cleanup.apply(&mut bridge).await;
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the first WaitProcess qualification VM".to_string()
            });
            report.first_vm = bridge;
            return Err(reason);
        }
    };
    let driver = Arc::new(QualificationHvfDriver::new(
        Arc::clone(&session),
        qualification.vm_rootfs.clone(),
        qualification.create.clone(),
    ));
    let service = match crate::HostRuntimeService::open(
        &qualification.state_root,
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => service,
        Err(error) => {
            report.first_vm = driver.shutdown().await;
            cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "failed to open the first durable Host service for WaitProcess: {error}"
            ));
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
                && qualification.start.target.generation == Some(record.generation)
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!(
                    "WaitProcess setup Create returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!("WaitProcess setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                "WaitProcess setup Create timed out".to_string(),
            )
            .await;
        }
    };
    let started = match timeout(
        QUALIFICATION_TIMEOUT,
        service.start(qualification.start.clone()),
    )
    .await
    {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && record.generation == created.generation
                && record.state.id() == qualification.create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!(
                    "WaitProcess setup Start returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!("WaitProcess setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                "WaitProcess setup Start timed out".to_string(),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &qualification.init_marker,
        &qualification.init_marker_contents,
        "first-owner WaitProcess init",
    )
    .await
    {
        return shutdown_setup_failure(service, driver, cleanup, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(started.generation);

    let exact_process = exact_process_target(&qualification.exec);
    let first_exec = match timeout(
        QUALIFICATION_TIMEOUT,
        service.exec(qualification.exec.clone()),
    )
    .await
    {
        Ok(Ok(process))
            if process.target == exact_process
                && process.pid.is_some_and(|pid| pid > 0)
                && process.terminal =>
        {
            process
        }
        Ok(Ok(process)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!("WaitProcess setup Exec returned invalid process {process:?}"),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!("WaitProcess setup Exec failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                "WaitProcess setup Exec timed out".to_string(),
            )
            .await;
        }
    };
    report.first_exec_pid = first_exec.pid;
    if let Err(reason) = wait_for_exact_marker(
        &qualification.exec_marker,
        &qualification.exec_marker_contents,
        "first-owner waitable Exec",
    )
    .await
    {
        return shutdown_setup_failure(service, driver, cleanup, report, reason).await;
    }
    report.first_exec_marker_verified = true;
    match (
        exec_journal_status(
            &qualification.state_root,
            &qualification.exec.context.operation_id,
            &exact_process,
        )
        .await,
        durable_exec_process(&qualification.state_root, &exact_process).await,
    ) {
        (Ok(ExecJournalStatus::Succeeded(journal)), Ok(durable))
            if journal == first_exec && durable == first_exec =>
        {
            report.exec_journal_succeeded_before_reopen = true;
        }
        (Ok(ExecJournalStatus::Succeeded(_)), Ok(_)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                "WaitProcess setup Exec durable response changed".to_string(),
            )
            .await;
        }
        (Ok(ExecJournalStatus::Prepared), _) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                "WaitProcess setup Exec journal remained prepared".to_string(),
            )
            .await;
        }
        (Err(reason), _) | (_, Err(reason)) => {
            return shutdown_setup_failure(service, driver, cleanup, report, reason).await;
        }
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.signal_process(qualification.signal_process.clone()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                format!("WaitProcess setup SignalProcess failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                "WaitProcess setup SignalProcess timed out".to_string(),
            )
            .await;
        }
    }
    match signal_process_journal_status(
        &qualification.state_root,
        &qualification.signal_process.context.operation_id,
        &exact_process,
    )
    .await
    {
        Ok(SignalProcessJournalStatus::SucceededEmpty) => {
            report.signal_process_journal_succeeded_before_reopen = true;
        }
        Ok(SignalProcessJournalStatus::Prepared) => {
            return shutdown_setup_failure(
                service,
                driver,
                cleanup,
                report,
                "WaitProcess setup SignalProcess journal remained prepared".to_string(),
            )
            .await;
        }
        Err(reason) => {
            return shutdown_setup_failure(service, driver, cleanup, report, reason).await;
        }
    }

    let expected_exit =
        crate::operation_reopen_replacement_report::wait_process::expected_wait_process_exit_status(
        );
    let response_delivered =
        qualification.stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut first_failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.wait_process(qualification.wait_process.clone()),
    )
    .await
    {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_interruption(report, error, qualification.stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Err(error)) => append_failure(
            &mut first_failure,
            format!(
                "{} did not deliver its completed WaitProcess response: {error}",
                qualification.stage.as_str()
            ),
        ),
        Ok(Ok(status)) if response_delivered => {
            report.first_operation_response_received = true;
            report.first_wait_exit_status = Some(status.clone());
            report.first_response_matches_expected_exit = status == expected_exit;
            if !report.first_response_matches_expected_exit {
                append_failure(
                    &mut first_failure,
                    format!("first WaitProcess returned unexpected status {status:?}"),
                );
            }
            report.disconnect_probe_attempted = true;
            match timeout(
                QUALIFICATION_TIMEOUT,
                service.state(StateRequest {
                    target: qualification.start.target.clone(),
                }),
            )
            .await
            {
                Ok(Err(error)) => {
                    if let Err(reason) = record_interruption(report, error, qualification.stage) {
                        append_failure(&mut first_failure, reason);
                    }
                }
                Ok(Ok(_)) => append_failure(
                    &mut first_failure,
                    format!(
                        "{} disconnect probe unexpectedly succeeded",
                        qualification.stage.as_str()
                    ),
                ),
                Err(_) => {
                    append_failure(&mut first_failure, "WaitProcess disconnect probe timed out")
                }
            }
        }
        Ok(Ok(status)) => append_failure(
            &mut first_failure,
            format!("first WaitProcess unexpectedly completed with {status:?}"),
        ),
        Err(_) => append_failure(&mut first_failure, "first WaitProcess timed out"),
    }
    report.first_operation_dispatches = driver.wait_process_calls();
    if qualification.stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.durable_running_retained = record.state.id() == qualification.create.id.as_str()
                && record.driver == DriverKind::LibkrunHvf
                && record.isolation == IsolationClass::DedicatedVm
                && record.generation == created.generation
                && record.config_digest == created.config_digest
                && *record.state.status() == ContainerState::Running
                && *record.state.pid() == report.first_created_pid;
            if !report.durable_running_retained {
                append_failure(
                    &mut first_failure,
                    "interrupted WaitProcess did not retain the exact running record",
                );
            }
        }
        Ok(records) => append_failure(
            &mut first_failure,
            format!(
                "interrupted WaitProcess retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut first_failure,
            format!("failed to inspect state after WaitProcess: {error}"),
        ),
    }
    match process_exit_cache(&qualification.state_root, &exact_process).await {
        Ok((record, cache)) => {
            report.process_exit_cached_before_reopen = cache.as_ref() == Some(&expected_exit);
            let expected_cache = response_delivered.then_some(&expected_exit);
            if record != first_exec || cache.as_ref() != expected_cache {
                append_failure(
                    &mut first_failure,
                    "durable process or exit cache did not match WaitProcess delivery",
                );
            }
        }
        Err(reason) => append_failure(&mut first_failure, reason),
    }

    let expected_driver_exec = DriverExecRequest {
        context: qualification.exec.context.clone(),
        target: exact_process.clone(),
        process: qualification.exec.process.clone(),
        io: qualification.exec.io.clone(),
    };
    let expected_driver_signal = DriverSignalProcessRequest {
        context: qualification.signal_process.context.clone(),
        target: exact_process.clone(),
        signal: qualification.signal_process.signal,
    };
    let create_identity = driver.create_identity();
    let start_identity = driver.start_identity();
    let exec_identity = driver.exec_identity();
    let signal_process_identity = driver.signal_process_identity();
    let wait_process_identity = driver.wait_process_identity();

    drop(service);
    report.first_vm = driver.shutdown().await;
    cleanup.apply(&mut report.first_vm).await;
    report.first_guest_runtime_clean = runtime_entries(&qualification.vm_rootfs)
        .await
        .is_ok_and(|entries| entries == qualification.baseline_runtime_entries);
    if let Some(request) = qualification.guest_qualification.as_ref() {
        match read_guest_qualification_evidence(&qualification.first_console, request).await {
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
                        &mut first_failure,
                        "Guest WaitProcess evidence did not match the qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut first_failure, reason),
        }
    }
    match reset_marker(&qualification.init_marker).await {
        Ok(()) => report.marker_reset_before_replacement = true,
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    match reset_marker(&qualification.exec_marker).await {
        Ok(()) => report.exec_marker_reset_before_replacement = true,
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    if !report.first_vm.is_success() {
        append_failure(
            &mut first_failure,
            report
                .first_vm
                .reason
                .clone()
                .unwrap_or_else(|| "first VM cleanup evidence failed".to_string()),
        );
    }
    if !report.first_guest_runtime_clean {
        append_failure(
            &mut first_failure,
            format!("first VM left {GUEST_RUNTIME_PREFIX} guest runtime state"),
        );
    }
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Exec", driver.exec_calls()),
        ("SignalProcess", driver.signal_process_calls()),
        ("WaitProcess", report.first_operation_dispatches),
    ] {
        if actual != 1 {
            append_failure(
                &mut first_failure,
                format!("first driver recorded {actual} {label} dispatches instead of one"),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "selected WaitProcess point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let create_identity = identity_or_expected(
        create_identity,
        &mut first_failure,
        (
            qualification.create.context.operation_id.clone(),
            qualification.start.target.clone(),
        ),
    );
    let start_identity = identity_or_expected(
        start_identity,
        &mut first_failure,
        (
            qualification.start.context.operation_id.clone(),
            qualification.start.target.clone(),
        ),
    );
    let exec_identity =
        identity_or_expected(exec_identity, &mut first_failure, expected_driver_exec);
    let signal_process_identity = identity_or_expected(
        signal_process_identity,
        &mut first_failure,
        expected_driver_signal,
    );
    let wait_process_identity = identity_or_expected(
        wait_process_identity,
        &mut first_failure,
        (exact_process.clone(), qualification.wait_process.timeout_ms),
    );
    if wait_process_identity != (exact_process, qualification.wait_process.timeout_ms) {
        append_failure(
            &mut first_failure,
            "first WaitProcess did not resolve the current target exactly",
        );
    }
    if let Some(reason) = first_failure {
        return Err(reason);
    }
    drop(driver);
    drop(session);
    Ok(FirstOwnerEvidence {
        create_identity,
        start_identity,
        exec_record: first_exec,
        exec_identity,
        signal_process_identity,
        wait_process_identity,
    })
}
