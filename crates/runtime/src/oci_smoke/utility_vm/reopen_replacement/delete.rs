use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{CapabilityStatus, DriverKind, HostPlatform, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest, IoMode,
    IsolationRequest, KillRequest, ListRequest, OciBundle, OciRuntimeService, OperationContext,
    OperationId, ProcessIo, Signal, StartRequest,
};
use tokio::time::timeout;

use super::super::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use super::super::{
    canonical_directory, fixed_rootfs, path_exists, runtime_entries, target, unique_nonce,
    GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use super::delete_support::{
    append_reason, delete_journal_status, failed, record_interruption, record_recovery_evidence,
    remove_marker_if_present, reset_marker, shutdown_setup_failure, DeleteJournalStatus,
};
use super::{
    append_failure, create_qualification_state_root, owner_identities_are_distinct,
    wait_for_replacement_marker, QualificationHvfDriver, QUALIFICATION_TIMEOUT,
};
use crate::agent_session::UtilityVmSession;
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::{OciVmOperationReopenReplacementReport, RuntimeDriver};

const SETUP_KILL_SIGNAL: i32 = 9;

pub(in crate::oci_smoke::utility_vm) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    let mut report =
        OciVmOperationReopenReplacementReport::initial_delete(HostPlatform::current(), stage);
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
                    "refusing to overwrite an existing Delete reopen qualification marker: {}",
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
    let exact_target = match target(&format!("delete-reopen-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let create_operation_id = match operation_id(&format!("delete-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("delete-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let kill_operation_id = match operation_id(&format!("delete-reopen-{nonce}-kill")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("delete-reopen-{nonce}-delete")) {
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
                format!("failed to construct Delete reopen Create attachments: {error}"),
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
            delete_operation_id.clone(),
            AgentOperation::Delete,
            stage,
        ) {
            Ok(request) => Some(request),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to construct Guest Delete qualification: {error}"),
                );
            }
        }
    } else {
        None
    };
    report.qualification_operation_id = Some(delete_operation_id.clone());
    report.setup_create_operation_id = Some(create_operation_id);
    report.container_id = Some(exact_target.id.clone());

    let state_root = console_directory.join(format!("a3s-oci-delete-reopen-{nonce}-state"));
    if let Err(reason) = create_qualification_state_root(&state_root).await {
        return failed(report, reason);
    }
    let first_console = console_directory.join(format!("a3s-oci-delete-reopen-{nonce}-first.log"));
    let replacement_console =
        console_directory.join(format!("a3s-oci-delete-reopen-{nonce}-replacement.log"));

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
                format!("Delete qualification marker remained: {}", marker.display()),
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
        AgentOperation::Delete,
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
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the first Delete qualification VM".to_string()
            });
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
                "failed to open the first durable Host service for Delete: {error}"
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
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Delete qualification setup Create returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!("Delete qualification setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Delete qualification setup Create exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
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
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Delete qualification setup Start returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!("Delete qualification setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Delete qualification setup Start exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_replacement_marker(marker).await {
        return shutdown_setup_failure(
            first_service,
            first_driver,
            first_cleanup,
            report,
            format!("Delete qualification setup workload failed: {reason}"),
        )
        .await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(created.generation);
    let first_start_identity = first_driver.start_identity()?;
    let signal = Signal::new(SETUP_KILL_SIGNAL)
        .map_err(|error| format!("failed to construct Delete setup Kill signal: {error}"))?;
    let kill = KillRequest {
        context: OperationContext::new(kill_operation_id.clone()),
        target: start.target.clone(),
        signal,
        all: true,
    };
    match timeout(QUALIFICATION_TIMEOUT, first_service.kill(kill.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none() => {}
        Ok(Ok(record)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Delete qualification setup Kill returned {} with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!("Delete qualification setup Kill failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Delete qualification setup Kill exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    }
    let first_kill_identity = first_driver.kill_identity()?;
    let delete = DeleteRequest {
        context: OperationContext::new(delete_operation_id.clone()),
        target: start.target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut first_failure = None;
    match timeout(QUALIFICATION_TIMEOUT, first_service.delete(delete.clone())).await {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_interruption(report, error, stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Err(error)) => append_failure(
            &mut first_failure,
            format!(
                "{} did not deliver its completed Delete response: {error}",
                stage.as_str()
            ),
        ),
        Ok(Ok(())) if response_delivered => {
            report.first_operation_response_received = true;
            report.disconnect_probe_attempted = true;
            match timeout(
                QUALIFICATION_TIMEOUT,
                first_driver.state(delete.target.clone()),
            )
            .await
            {
                Ok(Err(error)) => {
                    if let Err(reason) = record_interruption(report, error, stage) {
                        append_failure(&mut first_failure, reason);
                    }
                }
                Ok(Ok(_)) => append_failure(
                    &mut first_failure,
                    format!("{} disconnect probe unexpectedly succeeded", stage.as_str()),
                ),
                Err(_) => append_failure(
                    &mut first_failure,
                    format!(
                        "{} disconnect probe exceeded the {} second timeout",
                        stage.as_str(),
                        QUALIFICATION_TIMEOUT.as_secs()
                    ),
                ),
            }
        }
        Ok(Ok(())) => append_failure(
            &mut first_failure,
            "first Delete unexpectedly completed before owner replacement",
        ),
        Err(_) => append_failure(
            &mut first_failure,
            format!(
                "first Delete exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    report.first_operation_dispatches = first_driver.delete_calls();
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    match first_service.list(ListRequest::default()).await {
        Ok(records) if response_delivered && records.is_empty() => {
            report.first_durable_records_empty = true;
        }
        Ok(records) if !response_delivered && records.len() == 1 => {
            let record = &records[0];
            let exact_record = record.state.id() == create.id.as_str()
                && record.driver == DriverKind::LibkrunHvf
                && record.isolation == IsolationClass::DedicatedVm
                && record.generation == created.generation
                && record.config_digest == created.config_digest;
            report.durable_stopped_retained = exact_record
                && *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none();
            if !report.durable_stopped_retained {
                append_failure(
                    &mut first_failure,
                    format!(
                        "interrupted Delete retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut first_failure,
            format!(
                "interrupted Delete retained {} live records; response_delivered={response_delivered}",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut first_failure,
            format!("failed to inspect durable state after interrupted Delete: {error}"),
        ),
    }
    match delete_journal_status(state_root, &delete.context.operation_id, &delete.target).await {
        Ok(DeleteJournalStatus::Prepared) => {
            report.delete_journal_prepared_before_reopen = true;
        }
        Ok(DeleteJournalStatus::SucceededEmpty) => {
            report.delete_journal_succeeded_empty_before_reopen = true;
        }
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    let first_delete_identity = first_driver.delete_identity();
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
                        "Guest Delete evidence did not match the exact qualification",
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
    for (label, calls) in [
        ("Start", first_driver.start_calls()),
        ("Kill", first_driver.kill_calls()),
        ("Delete", first_driver.delete_calls()),
    ] {
        if calls != 1 {
            append_failure(
                &mut first_failure,
                format!("first driver recorded {calls} {label} dispatches instead of one"),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "selected Delete transport point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let first_delete_identity = match first_delete_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut first_failure, reason);
            (
                delete.context.operation_id.clone(),
                delete.target.clone(),
                delete.mode,
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
                "failed to launch the replacement Delete qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let replacement_driver = Arc::new(QualificationHvfDriver::with_delete_recovery(
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
            record_recovery_evidence(report, replacement_driver.as_ref());
            service
        }
        Err(error) => {
            record_recovery_evidence(report, replacement_driver.as_ref());
            report.replacement_vm = replacement_driver.shutdown().await;
            replacement_cleanup.apply(&mut report.replacement_vm).await;
            return Err(format!(
                "failed to reopen durable Host service around the replacement VM: {error}"
            ));
        }
    };

    let mut replacement_failure = None;
    let recovery_required = !response_delivered;
    let expected_recoveries = u32::from(recovery_required);
    if report.replacement_recovery_calls != expected_recoveries {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement driver recovered {} durable records instead of {expected_recoveries}",
                report.replacement_recovery_calls
            ),
        );
    }
    if report.replacement_rehydrated_created_record != recovery_required
        || report.replacement_rehydrated_running_record != recovery_required
        || report.replacement_rehydrated_stopped_record != recovery_required
    {
        append_failure(
            &mut replacement_failure,
            "replacement rehydration did not match the durable Delete outcome",
        );
    }
    if report.replacement_created_pid.is_some() != recovery_required {
        append_failure(
            &mut replacement_failure,
            "replacement running PID did not match the required Delete recovery path",
        );
    }
    match replacement_service.list(ListRequest::default()).await {
        Ok(records) if response_delivered && records.is_empty() => {}
        Ok(records) if !response_delivered && records.len() == 1 => {
            let record = &records[0];
            if record.state.id() != create.id.as_str()
                || record.generation != created.generation
                || record.driver != DriverKind::LibkrunHvf
                || record.isolation != IsolationClass::DedicatedVm
                || *record.state.status() != ContainerState::Stopped
                || record.state.pid().is_some()
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
        }
        Ok(records) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement recovery retained {} live records; response_delivered={response_delivered}",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("failed to inspect recovered durable Delete record: {error}"),
        ),
    }

    if response_delivered {
        match path_exists(marker).await {
            Ok(false) => {}
            Ok(true) => append_failure(
                &mut replacement_failure,
                "completed Delete unexpectedly rebuilt a replacement workload marker",
            ),
            Err(reason) => append_failure(&mut replacement_failure, reason),
        }
        if replacement_driver.create_identity().is_ok()
            || replacement_driver.start_identity().is_ok()
            || replacement_driver.kill_identity().is_ok()
            || replacement_driver.start_calls() != 0
            || replacement_driver.kill_calls() != 0
        {
            append_failure(
                &mut replacement_failure,
                "completed Delete unexpectedly dispatched replacement recovery operations",
            );
        }
    } else {
        match wait_for_replacement_marker(marker).await {
            Ok(()) => report.replacement_workload_verified = true,
            Err(reason) => append_failure(&mut replacement_failure, reason),
        }
        match replacement_driver.create_identity() {
            Ok(identity) => {
                report.setup_create_identity_reused = identity == first_create_identity
                    && identity.0 == create.context.operation_id
                    && identity.1.generation == Some(created.generation);
            }
            Err(reason) => append_failure(&mut replacement_failure, reason),
        }
        match replacement_driver.start_identity() {
            Ok(identity) => {
                report.setup_start_identity_reused = identity == first_start_identity
                    && identity.0 == start.context.operation_id
                    && identity.1 == start.target;
            }
            Err(reason) => append_failure(&mut replacement_failure, reason),
        }
        match replacement_driver.kill_identity() {
            Ok(identity) => {
                report.setup_kill_identity_reused = identity == first_kill_identity
                    && identity.0 == kill.context.operation_id
                    && identity.1 == kill.target
                    && identity.2 == kill.signal
                    && identity.3 == kill.all;
            }
            Err(reason) => append_failure(&mut replacement_failure, reason),
        }
        if !report.setup_create_identity_reused
            || !report.setup_start_identity_reused
            || !report.setup_kill_identity_reused
        {
            append_failure(
                &mut replacement_failure,
                "replacement recovery changed a setup lifecycle identity",
            );
        }
    }

    let delete_calls_before = replacement_driver.delete_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        replacement_service.delete(delete.clone()),
    )
    .await
    {
        Ok(Ok(())) => {
            report.operation_completed_after_reopen = true;
            report.generation_after_reopen = delete.target.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            report.stopped_only_delete_completed = true;
        }
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("replacement Delete failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement Delete exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    report.replacement_operation_dispatches = replacement_driver.delete_calls();
    report.operation_replayed_without_driver_dispatch =
        report.replacement_operation_dispatches == delete_calls_before;
    let expected_delete_dispatches = u32::from(!response_delivered);
    if report.replacement_operation_dispatches != expected_delete_dispatches {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement driver recorded {} Delete dispatches instead of {expected_delete_dispatches}",
                report.replacement_operation_dispatches
            ),
        );
    }
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut replacement_failure,
            "replacement Delete dispatch did not match the completed durable journal",
        );
    }
    if response_delivered {
        report.same_operation_id_reused = report.operation_completed_after_reopen
            && first_delete_identity
                == (
                    delete.context.operation_id.clone(),
                    delete.target.clone(),
                    delete.mode,
                )
            && report.replacement_operation_dispatches == 0;
    } else {
        match replacement_driver.delete_identity() {
            Ok(identity) => {
                report.same_operation_id_reused = identity == first_delete_identity
                    && identity.0 == delete.context.operation_id
                    && identity.1 == delete.target
                    && identity.2 == delete.mode;
            }
            Err(reason) => append_failure(&mut replacement_failure, reason),
        }
    }
    if !report.same_operation_id_reused {
        append_failure(
            &mut replacement_failure,
            "replacement path did not reuse the original Delete identity",
        );
    }
    match replacement_service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut replacement_failure,
                    format!(
                        "replacement Delete retained {} durable container records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("failed to inspect durable state after replacement Delete: {error}"),
        ),
    }
    match delete_journal_status(state_root, &delete.context.operation_id, &delete.target).await {
        Ok(DeleteJournalStatus::SucceededEmpty) => {
            report.delete_journal_succeeded_empty_after_reopen = true;
        }
        Ok(DeleteJournalStatus::Prepared) => append_failure(
            &mut replacement_failure,
            "replacement Delete left its durable journal prepared",
        ),
        Err(reason) => append_failure(&mut replacement_failure, reason),
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
        .map_err(|error| format!("failed to construct Delete qualification operation ID: {error}"))
}
