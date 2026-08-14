use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{CapabilityStatus, DriverKind, HostPlatform, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    IoMode, IsolationRequest, KillRequest, ListRequest, OciBundle, OciRuntimeService,
    OperationContext, OperationId, ProcessIo, Signal, StartRequest,
};
use tokio::time::timeout;

use super::super::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use super::super::{
    canonical_directory, fixed_rootfs, path_exists, remove_marker, runtime_entries, target,
    unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use super::{
    append_failure, container_operation_journal_status, create_qualification_state_root,
    owner_identities_are_distinct, wait_for_replacement_marker, ContainerOperationJournalStatus,
    QualificationHvfDriver, FAULT_OPERATION, QUALIFICATION_TIMEOUT,
};
use crate::agent_session::UtilityVmSession;
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{OciVmOperationReopenReplacementReport, RuntimeDriver};

const KILL_SIGNAL: i32 = 9;

pub(in crate::oci_smoke::utility_vm) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    let mut report =
        OciVmOperationReopenReplacementReport::initial_kill(HostPlatform::current(), stage);
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM rootfs").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let console_directory =
        match canonical_directory(console_directory, "qualification console directory").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
    if bundle_directory == vm_rootfs || !bundle_directory.starts_with(&vm_rootfs) {
        return failed(
            report,
            format!(
                "OCI bundle must be a strict descendant of VM rootfs {}: {}",
                vm_rootfs.display(),
                bundle_directory.display()
            ),
        );
    }

    let bundle = match OciBundle::load(&bundle_directory).await {
        Ok(bundle) => {
            report.bundle_loaded = true;
            bundle
        }
        Err(error) => return failed(report, format!("failed to load OCI bundle: {error}")),
    };
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let marker = rootfs.join(MARKER_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing Kill reopen qualification marker: {}",
                    marker.display()
                ),
            );
        }
        Err(reason) => return failed(report, reason),
    }
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let exact_target = match target(&format!("kill-reopen-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let create_operation_id = match operation_id(&format!("kill-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("kill-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let kill_operation_id = match operation_id(&format!("kill-reopen-{nonce}-kill")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("kill-reopen-{nonce}-delete")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let process_io = ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    };
    let attachments = match CreateAttachments::from_bundle(&bundle, process_io) {
        Ok(attachments) => attachments,
        Err(error) => {
            return failed(
                report,
                format!("failed to construct Kill reopen Create attachments: {error}"),
            );
        }
    };
    let create = CreateRequest {
        context: OperationContext::new(create_operation_id.clone()),
        id: exact_target.id.clone(),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments,
    };
    let guest_qualification = if stage.is_guest() {
        match AgentTransportQualificationRequest::new(
            kill_operation_id.clone(),
            AgentOperation::Kill,
            stage,
        ) {
            Ok(request) => Some(request),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to construct Guest Kill qualification: {error}"),
                );
            }
        }
    } else {
        None
    };
    report.qualification_operation_id = Some(kill_operation_id.clone());
    report.setup_create_operation_id = Some(create_operation_id);
    report.container_id = Some(exact_target.id.clone());

    let state_root = console_directory.join(format!("a3s-oci-kill-reopen-{nonce}-state"));
    if let Err(reason) = create_qualification_state_root(&state_root).await {
        return failed(report, reason);
    }
    let first_console = console_directory.join(format!("a3s-oci-kill-reopen-{nonce}-first.log"));
    let replacement_console =
        console_directory.join(format!("a3s-oci-kill-reopen-{nonce}-replacement.log"));

    let exercise = exercise(
        shim,
        &vm_rootfs,
        system_image_manifest,
        &state_root,
        &first_console,
        &replacement_console,
        &marker,
        &create,
        &start_operation_id,
        &kill_operation_id,
        &delete_operation_id,
        &baseline_runtime_entries,
        stage,
        guest_qualification.as_ref(),
        &mut report,
    )
    .await;

    match remove_marker_if_present(&marker).await {
        Ok(()) => match path_exists(&marker).await {
            Ok(false) => report.marker_absent_after_cleanup = true,
            Ok(true) => append_reason(
                &mut report,
                format!("Kill qualification marker remained: {}", marker.display()),
            ),
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(reason) => append_reason(&mut report, reason),
    }
    match tokio::fs::remove_dir_all(&state_root).await {
        Ok(()) => match path_exists(&state_root).await {
            Ok(false) => report.state_root_removed = true,
            Ok(true) => append_reason(
                &mut report,
                format!(
                    "qualification state root remained after removal: {}",
                    state_root.display()
                ),
            ),
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove qualification state root {}: {error}",
                state_root.display()
            ),
        ),
    }
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    marker: &Path,
    create: &CreateRequest,
    start_operation_id: &OperationId,
    kill_operation_id: &OperationId,
    delete_operation_id: &OperationId,
    baseline_runtime_entries: &std::collections::BTreeSet<String>,
    stage: AgentTransportOperationStage,
    guest_qualification: Option<&AgentTransportQualificationRequest>,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<(), String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::Kill,
        AgentTransportFaultStage::from(stage),
    ));
    let first_cleanup = MacosHostCleanupTracker::capture();
    let first_session_result = match guest_qualification {
        Some(qualification) => {
            UtilityVmSession::connect_with_guest_qualification(
                shim,
                vm_rootfs,
                Some(system_image_manifest),
                first_console,
                qualification,
            )
            .await
        }
        None => {
            UtilityVmSession::connect_with_host_fault_injector(
                shim,
                vm_rootfs,
                Some(system_image_manifest),
                first_console,
                Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>,
            )
            .await
        }
    };
    let first_session = match first_session_result {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            first_cleanup.apply(&mut bridge).await;
            let reason = bridge
                .reason
                .clone()
                .unwrap_or_else(|| "failed to launch the first Kill qualification VM".to_string());
            report.first_vm = bridge;
            return Err(reason);
        }
    };
    let first_driver = Arc::new(QualificationHvfDriver::new(
        Arc::clone(&first_session),
        vm_rootfs.to_path_buf(),
        create.clone(),
    ));
    let first_service = match crate::HostRuntimeService::open(
        state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => service,
        Err(error) => {
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "failed to open the first durable Host service for Kill: {error}"
            ));
        }
    };

    let created = match timeout(QUALIFICATION_TIMEOUT, first_service.create(create.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Created
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "Kill qualification setup Create returned invalid {} record with PID {:?}",
                record.state.status(),
                record.state.pid()
            ));
        }
        Ok(Err(error)) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!("Kill qualification setup Create failed: {error}"));
        }
        Err(_) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "Kill qualification setup Create exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ));
        }
    };
    let first_create_identity = first_driver.create_identity()?;
    let start = StartRequest {
        context: OperationContext::new(start_operation_id.clone()),
        target: ContainerTarget::exact(create.id.clone(), created.generation),
    };
    let started = match timeout(QUALIFICATION_TIMEOUT, first_service.start(start.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "Kill qualification setup Start returned invalid {} record with PID {:?}",
                record.state.status(),
                record.state.pid()
            ));
        }
        Ok(Err(error)) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!("Kill qualification setup Start failed: {error}"));
        }
        Err(_) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "Kill qualification setup Start exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ));
        }
    };
    if let Err(reason) = wait_for_replacement_marker(marker).await {
        drop(first_service);
        report.first_vm = first_driver.shutdown().await;
        first_cleanup.apply(&mut report.first_vm).await;
        return Err(format!(
            "Kill qualification setup workload failed: {reason}"
        ));
    }
    report.first_created_pid = *started.state.pid();
    let first_start_identity = first_driver.start_identity();
    let signal = match Signal::new(KILL_SIGNAL) {
        Ok(signal) => signal,
        Err(error) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "failed to construct Kill qualification signal: {error}"
            ));
        }
    };
    let kill = KillRequest {
        context: OperationContext::new(kill_operation_id.clone()),
        target: start.target.clone(),
        signal,
        all: true,
    };
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut first_failure = None;
    match timeout(QUALIFICATION_TIMEOUT, first_service.kill(kill.clone())).await {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Ok(record)) => append_failure(
            &mut first_failure,
            format!("first Kill unexpectedly completed before owner replacement: {record:?}"),
        ),
        Err(_) => append_failure(
            &mut first_failure,
            format!(
                "first Kill exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
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
                    &mut first_failure,
                    format!(
                        "completed Kill Host journal retained {} with PID {:?} instead of stopped",
                        response.state.status(),
                        response.state.pid()
                    ),
                );
            }
            Some(response)
        }
        Ok(ContainerOperationJournalStatus::Prepared) => {
            append_failure(
                &mut first_failure,
                "completed Kill response left its Host journal prepared",
            );
            None
        }
        Ok(ContainerOperationJournalStatus::Succeeded(response)) => {
            append_failure(
                &mut first_failure,
                format!("Kill Host journal committed before its response boundary: {response:?}"),
            );
            None
        }
        Err(reason) => {
            append_failure(&mut first_failure, reason);
            None
        }
    };
    report.first_operation_dispatches = first_driver.kill_calls();
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    match first_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_before_reopen = Some(record.generation);
            let exact_record = record.state.id() == create.id.as_str()
                && record.driver == DriverKind::LibkrunHvf
                && record.isolation == IsolationClass::DedicatedVm
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
                .is_some_and(|response| response == record);
            let expected_retained = if response_delivered {
                report.durable_stopped_retained && report.first_response_matches_durable_record
            } else {
                report.durable_running_retained
            };
            if !expected_retained {
                append_failure(
                    &mut first_failure,
                    format!(
                        "interrupted Kill retained {} instead of the exact durable {} record",
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
            &mut first_failure,
            format!(
                "interrupted Kill retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut first_failure,
            format!("failed to inspect durable state after interrupted Kill: {error}"),
        ),
    }
    let first_kill_identity = first_driver.kill_identity();
    drop(first_service);
    report.first_vm = first_driver.shutdown().await;
    first_cleanup.apply(&mut report.first_vm).await;
    report.first_guest_runtime_clean = runtime_entries(vm_rootfs)
        .await
        .is_ok_and(|entries| &entries == baseline_runtime_entries);
    if let Some(qualification) = guest_qualification {
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
                        &mut first_failure,
                        "Guest Kill evidence did not match the exact qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut first_failure, reason),
        }
    }
    match reset_marker(marker).await {
        Ok(()) => report.marker_reset_before_replacement = true,
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
    if first_driver.start_calls() != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "first driver recorded {} setup Start dispatches instead of one",
                first_driver.start_calls()
            ),
        );
    }
    if report.first_operation_dispatches != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "first driver recorded {} Kill dispatches instead of one",
                report.first_operation_dispatches
            ),
        );
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "selected Kill transport point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let first_start_identity = match first_start_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut first_failure, reason);
            (start.context.operation_id.clone(), start.target.clone())
        }
    };
    let first_kill_identity = match first_kill_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut first_failure, reason);
            (
                kill.context.operation_id.clone(),
                kill.target.clone(),
                kill.signal,
                kill.all,
            )
        }
    };
    if let Some(reason) = first_failure {
        return Err(reason);
    }
    drop(first_driver);
    drop(first_session);

    let replacement_cleanup = MacosHostCleanupTracker::capture();
    let replacement_session = match UtilityVmSession::connect(
        shim,
        vm_rootfs,
        Some(system_image_manifest),
        replacement_console,
    )
    .await
    {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            replacement_cleanup.apply(&mut bridge).await;
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the replacement Kill qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let replacement_driver = Arc::new(QualificationHvfDriver::with_kill_recovery(
        Arc::clone(&replacement_session),
        vm_rootfs.to_path_buf(),
        create.clone(),
        start.clone(),
        kill.clone(),
        marker.to_path_buf(),
    ));
    let replacement_service = match crate::HostRuntimeService::open(
        state_root,
        Arc::clone(&replacement_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => {
            report.host_service_reopened = true;
            report.replacement_recovery_calls = replacement_driver.recovery_calls();
            report.replacement_rehydrated_created_record =
                replacement_driver.rehydrated_created_record();
            report.replacement_rehydrated_running_record =
                replacement_driver.rehydrated_running_record();
            report.replacement_rehydrated_stopped_record =
                replacement_driver.rehydrated_stopped_record();
            report.replacement_created_pid = replacement_driver.rehydrated_running_pid();
            service
        }
        Err(error) => {
            report.replacement_recovery_calls = replacement_driver.recovery_calls();
            report.replacement_rehydrated_created_record =
                replacement_driver.rehydrated_created_record();
            report.replacement_rehydrated_running_record =
                replacement_driver.rehydrated_running_record();
            report.replacement_rehydrated_stopped_record =
                replacement_driver.rehydrated_stopped_record();
            report.replacement_created_pid = replacement_driver.rehydrated_running_pid();
            report.replacement_vm = replacement_driver.shutdown().await;
            replacement_cleanup.apply(&mut report.replacement_vm).await;
            return Err(format!(
                "failed to reopen durable Host service around the replacement VM: {error}"
            ));
        }
    };

    let mut replacement_failure = None;
    if report.replacement_recovery_calls != 1 {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement driver recovered {} durable records instead of one",
                report.replacement_recovery_calls
            ),
        );
    }
    if !report.replacement_rehydrated_created_record {
        append_failure(
            &mut replacement_failure,
            "replacement driver did not rebuild the durable pre-start process",
        );
    }
    if !report.replacement_rehydrated_running_record {
        append_failure(
            &mut replacement_failure,
            "replacement driver did not restart the durable Kill process",
        );
    }
    if report.replacement_rehydrated_stopped_record != response_delivered {
        append_failure(
            &mut replacement_failure,
            "replacement stopped rehydration did not match the durable Kill outcome",
        );
    }
    if report.replacement_created_pid.is_none() {
        append_failure(
            &mut replacement_failure,
            "replacement recovery did not retain its positive running PID",
        );
    }
    let recovered = match replacement_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = records[0].clone();
            let expected_status = if response_delivered {
                ContainerState::Stopped
            } else {
                ContainerState::Running
            };
            let expected_pid = if response_delivered {
                record.state.pid().is_none()
            } else {
                *record.state.pid() == report.replacement_created_pid
            };
            if record.state.id() != create.id.as_str()
                || record.generation != created.generation
                || record.driver != DriverKind::LibkrunHvf
                || record.isolation != IsolationClass::DedicatedVm
                || *record.state.status() != expected_status
                || !expected_pid
            {
                append_failure(
                    &mut replacement_failure,
                    format!(
                        "replacement recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
            Some(record)
        }
        Ok(records) => {
            append_failure(
                &mut replacement_failure,
                format!(
                    "replacement recovery retained {} durable records instead of one",
                    records.len()
                ),
            );
            None
        }
        Err(error) => {
            append_failure(
                &mut replacement_failure,
                format!("failed to inspect recovered durable Kill record: {error}"),
            );
            None
        }
    };

    if !response_delivered {
        let replacement_create = match timeout(
            QUALIFICATION_TIMEOUT,
            replacement_service.create(create.clone()),
        )
        .await
        {
            Ok(Ok(record)) => Some(record),
            Ok(Err(error)) => {
                append_failure(
                    &mut replacement_failure,
                    format!("replacement Create journal replay failed: {error}"),
                );
                None
            }
            Err(_) => {
                append_failure(
                    &mut replacement_failure,
                    format!(
                        "replacement Create journal replay exceeded the {} second timeout",
                        QUALIFICATION_TIMEOUT.as_secs()
                    ),
                );
                None
            }
        };
        if let (Some(recovered), Some(replayed_create)) = (&recovered, &replacement_create) {
            report.setup_create_response_rebound = *replayed_create.state.status()
                == ContainerState::Created
                && replayed_create.generation == recovered.generation
                && *replayed_create.state.pid() == report.replacement_created_pid;
            if !report.setup_create_response_rebound {
                append_failure(
                    &mut replacement_failure,
                    "replacement Create replay did not bind to the fresh process identity",
                );
            }
        }

        match timeout(
            QUALIFICATION_TIMEOUT,
            replacement_service.start(start.clone()),
        )
        .await
        {
            Ok(Ok(record)) => {
                report.setup_start_response_rebound = *record.state.status()
                    == ContainerState::Running
                    && record.generation == created.generation
                    && *record.state.pid() == report.replacement_created_pid;
                if !report.setup_start_response_rebound {
                    append_failure(
                        &mut replacement_failure,
                        "replacement Start replay did not bind to the fresh process identity",
                    );
                }
            }
            Ok(Err(error)) => append_failure(
                &mut replacement_failure,
                format!("replacement Start journal replay failed: {error}"),
            ),
            Err(_) => append_failure(
                &mut replacement_failure,
                format!(
                    "replacement Start journal replay exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            ),
        }
    }

    match wait_for_replacement_marker(marker).await {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }

    let kill_calls_before = replacement_driver.kill_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        replacement_service.kill(kill.clone()),
    )
    .await
    {
        Ok(Ok(record)) => {
            report.generation_after_reopen = Some(record.generation);
            report.operation_completed_after_reopen =
                *record.state.status() == ContainerState::Stopped && record.state.pid().is_none();
            report.replacement_response_matches_durable_record = replacement_service
                .list(ListRequest::default())
                .await
                .is_ok_and(|records| records.len() == 1 && records[0] == record);
            report.same_generation_reused =
                report.generation_before_reopen == Some(record.generation);
            if !report.operation_completed_after_reopen {
                append_failure(
                    &mut replacement_failure,
                    "replacement Kill did not reach the OCI stopped state",
                );
            }
            if !report.replacement_response_matches_durable_record {
                append_failure(
                    &mut replacement_failure,
                    "replacement Kill response differed from the durable record",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement Kill did not reuse the original durable generation",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("replacement Kill failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement Kill exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    report.replacement_operation_dispatches = replacement_driver.kill_calls();
    report.operation_replayed_without_driver_dispatch =
        report.replacement_operation_dispatches == kill_calls_before;
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement driver recorded {} Kill dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut replacement_failure,
            "replacement Kill dispatch did not match the completed durable journal",
        );
    }
    if replacement_driver.start_calls() != 1 {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement driver recorded {} setup Start dispatches instead of one",
                replacement_driver.start_calls()
            ),
        );
    }
    match replacement_driver.create_identity() {
        Ok(replacement_create_identity) => {
            report.setup_create_identity_reused = replacement_create_identity
                == first_create_identity
                && replacement_create_identity.0 == create.context.operation_id
                && replacement_create_identity.1.generation == report.generation_before_reopen;
            if !report.setup_create_identity_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement recovery did not reuse the setup Create identity and generation",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }
    match replacement_driver.start_identity() {
        Ok(replacement_start_identity) => {
            report.setup_start_identity_reused = replacement_start_identity == first_start_identity
                && replacement_start_identity.0 == start.context.operation_id
                && replacement_start_identity.1 == start.target;
            if !report.setup_start_identity_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement recovery did not reuse the setup Start identity and target",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }
    match replacement_driver.kill_identity() {
        Ok(replacement_kill_identity) => {
            report.same_operation_id_reused = replacement_kill_identity == first_kill_identity
                && replacement_kill_identity.0 == kill.context.operation_id
                && replacement_kill_identity.1 == kill.target
                && replacement_kill_identity.2 == kill.signal
                && replacement_kill_identity.3 == kill.all;
            if !report.same_operation_id_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement recovery did not reuse the original Kill identity and target",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }

    if let Some(generation) = report.generation_before_reopen {
        let delete = DeleteRequest {
            context: OperationContext::new(delete_operation_id.clone()),
            target: ContainerTarget::exact(create.id.clone(), generation),
            mode: DeleteMode::StoppedOnly,
        };
        match timeout(QUALIFICATION_TIMEOUT, replacement_service.delete(delete)).await {
            Ok(Ok(())) => report.stopped_only_delete_completed = true,
            Ok(Err(error)) => append_failure(
                &mut replacement_failure,
                format!("replacement stopped-only delete failed: {error}"),
            ),
            Err(_) => append_failure(
                &mut replacement_failure,
                format!(
                    "replacement stopped-only delete exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            ),
        }
    } else {
        append_failure(
            &mut replacement_failure,
            "replacement cleanup had no retained durable generation",
        );
    }
    match replacement_service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut replacement_failure,
                    format!(
                        "replacement delete retained {} durable container records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("failed to inspect durable state after replacement delete: {error}"),
        ),
    }
    drop(replacement_service);
    report.replacement_vm = replacement_driver.shutdown().await;
    replacement_cleanup.apply(&mut report.replacement_vm).await;
    report.replacement_guest_runtime_clean = runtime_entries(vm_rootfs)
        .await
        .is_ok_and(|entries| &entries == baseline_runtime_entries);
    report.owners_distinct =
        owner_identities_are_distinct(&report.first_vm, &report.replacement_vm);
    if !report.replacement_vm.is_success() {
        append_failure(
            &mut replacement_failure,
            report
                .replacement_vm
                .reason
                .clone()
                .unwrap_or_else(|| "replacement VM cleanup evidence failed".to_string()),
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut replacement_failure,
            format!("replacement VM left {GUEST_RUNTIME_PREFIX} guest runtime state"),
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut replacement_failure,
            "first and replacement VM owner identities were not distinct",
        );
    }
    replacement_failure.map_or(Ok(()), Err)
}

fn operation_id(value: &str) -> std::result::Result<OperationId, String> {
    OperationId::new(value)
        .map_err(|error| format!("failed to construct Kill qualification operation ID: {error}"))
}

fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first owner returned an unexpected Kill transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

async fn reset_marker(marker: &Path) -> std::result::Result<(), String> {
    remove_marker_if_present(marker).await?;
    if path_exists(marker).await? {
        return Err(format!(
            "first-owner marker remained before replacement: {}",
            marker.display()
        ));
    }
    Ok(())
}

async fn remove_marker_if_present(marker: &Path) -> std::result::Result<(), String> {
    if path_exists(marker).await? {
        remove_marker(marker).await?;
    }
    Ok(())
}

fn append_reason(report: &mut OciVmOperationReopenReplacementReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmOperationReopenReplacementReport,
    reason: impl Into<String>,
) -> OciVmOperationReopenReplacementReport {
    append_reason(&mut report, reason);
    report
}
