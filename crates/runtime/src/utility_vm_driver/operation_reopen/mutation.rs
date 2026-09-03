use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, ErrorCode, FileRequest,
    FileResponse, FilesystemRequest, FilesystemResponse, Generation, ListRequest,
    OciRuntimeService, OperationContext, OperationId, StartRequest,
};
use tokio::time::timeout;

use super::driver::QualificationKvmOperationDriver;
use super::exec::{stale_target, wait_for_exact_marker};
use super::mutation_support::{
    append_failure, changed_upload_data, directory_response_matches, download_response_matches,
    empty_filesystem_response, file_mutation_journal_status, filesystem_mutation_journal_status,
    record_interruption, upload_response_matches, FileMutationJournalStatus,
    FilesystemMutationJournalStatus,
};
use super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::{owner_identities_are_distinct, runtime_entries_clean, QUALIFICATION_TIMEOUT};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::RuntimeDriver;
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

#[derive(Debug, Clone)]
pub(super) enum Mutation {
    File {
        request: FileRequest,
        download: FileRequest,
        cleanup: FilesystemRequest,
        expected_payload: Vec<u8>,
    },
    Filesystem {
        request: FilesystemRequest,
        stat: FilesystemRequest,
        cleanup: FilesystemRequest,
    },
}

impl Mutation {
    fn agent_operation(&self) -> AgentOperation {
        match self {
            Self::File { .. } => AgentOperation::File,
            Self::Filesystem { .. } => AgentOperation::Filesystem,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::File { .. } => "File",
            Self::Filesystem { .. } => "Filesystem",
        }
    }

    fn operation_id(&self) -> Result<&OperationId, String> {
        let context = match self {
            Self::File { request, .. } => request.context.as_ref(),
            Self::Filesystem { request, .. } => request.context.as_ref(),
        };
        context.map(|context| &context.operation_id).ok_or_else(|| {
            format!(
                "KVM {} qualification has no operation context",
                self.label()
            )
        })
    }

    fn exact_identity(&self, target: &ContainerTarget) -> MutationIdentity {
        match self {
            Self::File { request, .. } => MutationIdentity::File(FileRequest {
                target: target.clone(),
                ..request.clone()
            }),
            Self::Filesystem { request, .. } => MutationIdentity::Filesystem(FilesystemRequest {
                target: target.clone(),
                ..request.clone()
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MutationIdentity {
    File(FileRequest),
    Filesystem(FilesystemRequest),
}

#[derive(Debug, Clone)]
pub(super) struct Qualification {
    pub(super) create: CreateRequest,
    pub(super) start_operation_id: OperationId,
    pub(super) delete_operation_id: OperationId,
    pub(super) stale_guest_operation_id: OperationId,
    pub(super) stale_host_operation_id: OperationId,
    pub(super) mutation: Mutation,
    pub(super) init_marker_contents: Vec<u8>,
    pub(super) stage: AgentTransportOperationStage,
}

struct FirstOwnerOutcome {
    target: ContainerTarget,
    mount_root: PathBuf,
    init_marker: PathBuf,
    create_identity: (OperationId, ContainerTarget),
    start_identity: (OperationId, ContainerTarget),
    mutation_identity: MutationIdentity,
    start: StartRequest,
    response_delivered: bool,
}

pub(super) async fn exercise(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let first = first_owner(prepared, state_root, first_console, qualification, report).await?;
    replacement_owner(
        prepared,
        state_root,
        replacement_console,
        qualification,
        first,
        report,
    )
    .await
}

async fn first_owner(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<FirstOwnerOutcome, String> {
    let operation = qualification.mutation.agent_operation();
    let operation_id = qualification.mutation.operation_id()?.clone();
    let label = qualification.mutation.label();
    let faults = Arc::new(HostTransportFault::for_operation(
        operation,
        AgentTransportFaultStage::from(qualification.stage),
    ));
    let guest_qualification = if qualification.stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(operation_id, operation, qualification.stage)
                .map_err(|error| {
                format!("failed to construct Guest KVM {label} qualification: {error}")
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
                return Err(format!(
                    "failed to open first KVM Host service for {label}: {error}"
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
                    "KVM {label} setup Create returned invalid {} record with PID {:?}",
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
                format!("KVM {label} setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return setup_failure(
                &driver,
                report,
                format!("KVM {label} setup Create timed out"),
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
    match path_absent(&init_marker).await {
        Ok(true) => {}
        Ok(false) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!(
                    "KVM {label} init marker existed before setup Start: {}",
                    init_marker.display()
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
                    "KVM {label} setup Start returned invalid {} record with PID {:?}",
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
                format!("KVM {label} setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(service);
            return active_failure(
                &driver,
                &target,
                report,
                format!("KVM {label} setup Start timed out"),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_exact_marker(
        &init_marker,
        &qualification.init_marker_contents,
        &format!("first-owner KVM {label} init"),
    )
    .await
    {
        drop(service);
        return active_failure(&driver, &target, report, reason).await;
    }
    report.first_created_pid = *started.state.pid();
    report.generation_before_reopen = Some(started.generation);

    let response_delivered =
        qualification.stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_host_mutation(&service, &qualification.mutation),
    )
    .await
    {
        Ok(Err(error)) => {
            if let Err(reason) = record_interruption(report, error, qualification.stage, label) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!(
                "first KVM {label} unexpectedly completed before owner replacement: {response:?}"
            ),
        ),
        Err(_) => append_failure(&mut failure, format!("first KVM {label} timed out")),
    }
    match mutation_journal_status(state_root, &qualification.mutation, &target).await {
        Ok(MutationJournalStatus::Prepared) if !response_delivered => {}
        Ok(MutationJournalStatus::Succeeded(response)) if response_delivered => {
            report.first_response_matches_durable_record =
                response_matches(&response, &qualification.mutation, &target);
            if !report.first_response_matches_durable_record {
                append_failure(
                    &mut failure,
                    format!("first KVM {label} journal retained an invalid response: {response:?}"),
                );
            }
        }
        Ok(MutationJournalStatus::Prepared) => append_failure(
            &mut failure,
            format!("completed KVM {label} response left its Host journal prepared"),
        ),
        Ok(MutationJournalStatus::Succeeded(response)) => append_failure(
            &mut failure,
            format!(
                "KVM {label} Host journal committed before the selected response boundary: {response:?}"
            ),
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    report.first_operation_dispatches = mutation_calls(&driver, &qualification.mutation);
    if qualification.stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
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
                    format!(
                        "interrupted KVM {label} did not retain the exact durable running record"
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "interrupted KVM {label} retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect state after interrupted KVM {label}: {error}"),
        ),
    }

    let start_identity = driver.start_identity();
    let mutation_identity = driver_mutation_identity(&driver, &qualification.mutation);
    let expected_mutation_identity = qualification.mutation.exact_identity(&target);
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
                        format!("Guest KVM {label} evidence did not match the exact qualification"),
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
            format!("first KVM {label} owner left Guest Agent runtime state"),
        );
    }
    for (operation_name, calls) in [
        ("Start", driver.start_calls()),
        (label, report.first_operation_dispatches),
    ] {
        if calls != 1 {
            append_failure(
                &mut failure,
                format!(
                    "first KVM driver recorded {calls} {operation_name} dispatches instead of one"
                ),
            );
        }
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut failure,
            format!(
                "selected KVM {label} point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let start_identity = start_identity.unwrap_or_else(|reason| {
        append_failure(&mut failure, reason);
        (start.context.operation_id.clone(), start.target.clone())
    });
    let mutation_identity = mutation_identity.unwrap_or_else(|reason| {
        append_failure(&mut failure, reason);
        expected_mutation_identity
    });
    if let Some(reason) = failure {
        return cleanup_failure(&driver, &target, reason).await;
    }
    drop(driver);
    Ok(FirstOwnerOutcome {
        target,
        mount_root,
        init_marker,
        create_identity,
        start_identity,
        mutation_identity,
        start,
        response_delivered,
    })
}

async fn replacement_owner(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    replacement_console: &Path,
    qualification: &Qualification,
    first: FirstOwnerOutcome,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let label = qualification.mutation.label();
    let recovery_marker = first.response_delivered.then(|| {
        (
            first.init_marker.clone(),
            qualification.init_marker_contents.clone(),
        )
    });
    let driver = Arc::new(match &qualification.mutation {
        Mutation::File { request, .. } => QualificationKvmOperationDriver::with_file_recovery(
            prepared,
            replacement_console.to_path_buf(),
            qualification.create.clone(),
            first.start.clone(),
            first.response_delivered.then(|| request.clone()),
            recovery_marker,
        ),
        Mutation::Filesystem { request, .. } => {
            QualificationKvmOperationDriver::with_filesystem_recovery(
                prepared,
                replacement_console.to_path_buf(),
                qualification.create.clone(),
                first.start.clone(),
                first.response_delivered.then(|| request.clone()),
                recovery_marker,
            )
        }
    });
    let service =
        match HostRuntimeService::open(state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
        {
            Ok(service) => {
                report.host_service_reopened = true;
                capture_recovery(&driver, &qualification.mutation, report);
                service
            }
            Err(error) => {
                capture_recovery(&driver, &qualification.mutation, report);
                report.replacement_vm = driver.shutdown().await;
                let cleanup = driver.cleanup(&first.target).await;
                return match cleanup {
                    Ok(()) => Err(format!(
                        "failed to reopen KVM Host service for {label}: {error}"
                    )),
                    Err(cleanup) => Err(format!(
                        "failed to reopen KVM Host service for {label}: {error}; {cleanup}"
                    )),
                };
            }
        };

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
    let mutation_rehydrated = match &qualification.mutation {
        Mutation::File { .. } => report.replacement_rehydrated_file,
        Mutation::Filesystem { .. } => report.replacement_rehydrated_filesystem,
    };
    if !report.replacement_rehydrated_created_record
        || !report.replacement_rehydrated_running_record
        || report.replacement_rehydrated_stopped_record
        || report.replacement_rehydrated_exec_record
        || mutation_rehydrated != first.response_delivered
    {
        append_failure(
            &mut failure,
            format!("replacement KVM driver did not rebuild the exact running {label} state"),
        );
    }
    if report.replacement_created_pid.is_none() || report.replacement_exec_pid.is_some() {
        append_failure(
            &mut failure,
            format!("replacement KVM {label} recovery retained invalid PID evidence"),
        );
    }
    match service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            if record.state.id() != qualification.create.id.as_str()
                || first.target.generation != Some(record.generation)
                || record.driver != DriverKind::LibkrunKvm
                || record.isolation != IsolationClass::DedicatedVm
                || *record.state.status() != ContainerState::Running
                || record.is_paused()
                || *record.state.pid() != report.replacement_created_pid
            {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM {label} recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut failure,
            format!(
                "replacement KVM {label} recovery retained {} records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut failure,
            format!("failed to inspect recovered KVM {label} record: {error}"),
        ),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.create(qualification.create.clone()),
    )
    .await
    {
        Ok(Ok(record)) => {
            report.setup_create_response_rebound = *record.state.status()
                == ContainerState::Created
                && !record.is_paused()
                && first.target.generation == Some(record.generation)
                && *record.state.pid() == report.replacement_created_pid;
            if !report.setup_create_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement KVM Create replay did not bind to the fresh init PID",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Create journal replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Create replay timed out"),
    }
    match timeout(QUALIFICATION_TIMEOUT, service.start(first.start.clone())).await {
        Ok(Ok(record)) => {
            report.setup_start_response_rebound = *record.state.status() == ContainerState::Running
                && !record.is_paused()
                && first.target.generation == Some(record.generation)
                && *record.state.pid() == report.replacement_created_pid;
            if !report.setup_start_response_rebound {
                append_failure(
                    &mut failure,
                    "replacement KVM Start replay did not bind to the fresh init PID",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Start journal replay failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM Start replay timed out"),
    }
    match wait_for_exact_marker(
        &first.init_marker,
        &qualification.init_marker_contents,
        &format!("replacement KVM {label} init"),
    )
    .await
    {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut failure, reason),
    }

    if !first.response_delivered {
        match timeout(
            QUALIFICATION_TIMEOUT,
            direct_effect_query(&driver, &qualification.mutation, &first.target),
        )
        .await
        {
            Ok(Err(error)) if error.code == ErrorCode::NotFound => {}
            Ok(Err(error)) => append_failure(
                &mut failure,
                format!(
                    "fresh replacement KVM Guest returned the wrong pre-{label} error: {error}"
                ),
            ),
            Ok(Ok(response)) => append_failure(
                &mut failure,
                format!(
                    "fresh replacement KVM Guest retained an uncommitted {label} effect: {response:?}"
                ),
            ),
            Err(_) => append_failure(
                &mut failure,
                format!("fresh replacement KVM Guest pre-{label} check timed out"),
            ),
        }
    }

    let calls_before_mutation = mutation_calls(&driver, &qualification.mutation);
    let replacement_response = match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_host_mutation(&service, &qualification.mutation),
    )
    .await
    {
        Ok(Ok(response)) => {
            let response_valid =
                response_matches(&response, &qualification.mutation, &first.target);
            set_replacement_response_verified(report, &qualification.mutation, response_valid);
            report.operation_completed_after_reopen = response_valid;
            report.generation_after_reopen = response_generation(&response);
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !response_valid || !report.same_generation_reused {
                append_failure(
                    &mut failure,
                    format!("replacement KVM {label} returned an invalid response: {response:?}"),
                );
            }
            Some(response)
        }
        Ok(Err(error)) => {
            append_failure(
                &mut failure,
                format!("replacement KVM {label} failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(&mut failure, format!("replacement KVM {label} timed out"));
            None
        }
    };
    report.operation_replayed_without_driver_dispatch =
        mutation_calls(&driver, &qualification.mutation) == calls_before_mutation;
    match mutation_journal_status(state_root, &qualification.mutation, &first.target).await {
        Ok(MutationJournalStatus::Succeeded(journal)) => {
            report.replacement_response_matches_durable_record =
                replacement_response.as_ref() == Some(&journal);
            if !report.replacement_response_matches_durable_record {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM {label} response did not match its durable Host journal"
                    ),
                );
            }
        }
        Ok(MutationJournalStatus::Prepared) => append_failure(
            &mut failure,
            format!("replacement KVM {label} Host journal remained prepared"),
        ),
        Err(reason) => append_failure(&mut failure, reason),
    }
    let replay_calls_before = mutation_calls(&driver, &qualification.mutation);
    match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_host_mutation(&service, &qualification.mutation),
    )
    .await
    {
        Ok(Ok(response)) => {
            let replayed = replacement_response.as_ref() == Some(&response)
                && mutation_calls(&driver, &qualification.mutation) == replay_calls_before;
            set_response_replayed(report, &qualification.mutation, replayed);
            if !replayed {
                append_failure(
                    &mut failure,
                    format!(
                        "durable KVM Host did not replay the exact {label} response without dispatch"
                    ),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} replay failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} replay timed out"),
        ),
    }
    report.replacement_operation_dispatches = mutation_calls(&driver, &qualification.mutation);
    if report.operation_replayed_without_driver_dispatch != first.response_delivered {
        append_failure(
            &mut failure,
            format!("replacement KVM {label} dispatch did not match the durable journal outcome"),
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM driver recorded {} {label} dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }
    if driver.start_calls() != 1 {
        append_failure(
            &mut failure,
            format!(
                "replacement KVM recovery recorded {} Start dispatches instead of one",
                driver.start_calls()
            ),
        );
    }

    match driver.create_identity() {
        Ok(identity) => {
            report.setup_create_identity_reused = identity == first.create_identity;
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
            report.setup_start_identity_reused = identity == first.start_identity;
            if !report.setup_start_identity_reused {
                append_failure(
                    &mut failure,
                    "replacement KVM recovery changed the setup Start identity",
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }
    match driver_mutation_identity(&driver, &qualification.mutation) {
        Ok(identity) => {
            let identity_reused = identity == first.mutation_identity;
            set_request_identity_reused(report, &qualification.mutation, identity_reused);
            report.same_operation_id_reused = identity_reused
                && mutation_identity_operation_id(&identity)
                    == qualification.mutation.operation_id().ok()
                && mutation_identity_target(&identity) == &first.target;
            if !identity_reused || !report.same_operation_id_reused {
                append_failure(
                    &mut failure,
                    format!(
                        "replacement KVM {label} changed its operation, target, or payload identity"
                    ),
                );
            }
        }
        Err(reason) => append_failure(&mut failure, reason),
    }

    let calls_before_changed = mutation_calls(&driver, &qualification.mutation);
    match dispatch_changed_host_mutation(&service, &qualification.mutation).await {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && mutation_calls(&driver, &qualification.mutation) == calls_before_changed =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong changed {label} error: {error}"),
        ),
        Ok(response) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted changed {label} request: {response:?}"),
        ),
    }

    let stale_container = match stale_target(&first.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(&mut failure, reason);
            first.target.clone()
        }
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        dispatch_stale_guest_mutation(
            &driver,
            &qualification.mutation,
            stale_container.clone(),
            qualification.stale_guest_operation_id.clone(),
        ),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest returned the wrong stale {label} error: {error}"),
        ),
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement KVM Guest accepted stale {label}: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM Guest stale {label} check timed out"),
        ),
    }
    let stale_host_calls = mutation_calls(&driver, &qualification.mutation);
    match dispatch_stale_host_mutation(
        &service,
        &qualification.mutation,
        stale_container,
        qualification.stale_host_operation_id.clone(),
    )
    .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && mutation_calls(&driver, &qualification.mutation) == stale_host_calls =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut failure,
            format!("reopened KVM Host returned the wrong stale {label} error: {error}"),
        ),
        Ok(response) => append_failure(
            &mut failure,
            format!("reopened KVM Host accepted stale {label}: {response:?}"),
        ),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        direct_effect_query(&driver, &qualification.mutation, &first.target),
    )
    .await
    {
        Ok(Ok(response)) => {
            let verified = effect_matches(&response, &qualification.mutation, &first.target);
            set_effect_verified(report, &qualification.mutation, verified);
            if !verified {
                append_failure(
                    &mut failure,
                    format!("replacement KVM {label} effect was invalid: {response:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} effect query failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} effect query timed out"),
        ),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        direct_effect_cleanup(&driver, &qualification.mutation, &first.target),
    )
    .await
    {
        Ok(Ok(response)) if empty_filesystem_response(&response, &first.target) => {}
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup returned invalid metadata: {response:?}"),
        ),
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup timed out"),
        ),
    }
    match timeout(
        QUALIFICATION_TIMEOUT,
        direct_effect_query(&driver, &qualification.mutation, &first.target),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            set_effect_absent(report, &qualification.mutation, true);
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup check returned the wrong error: {error}"),
        ),
        Ok(Ok(response)) => append_failure(
            &mut failure,
            format!("replacement KVM {label} effect remained after cleanup: {response:?}"),
        ),
        Err(_) => append_failure(
            &mut failure,
            format!("replacement KVM {label} cleanup check timed out"),
        ),
    }

    match timeout(
        QUALIFICATION_TIMEOUT,
        service.delete(DeleteRequest {
            context: OperationContext::new(qualification.delete_operation_id.clone()),
            target: first.target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await
    {
        Ok(Ok(())) => report.force_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!("replacement KVM force Delete failed: {error}"),
        ),
        Err(_) => append_failure(&mut failure, "replacement KVM force Delete timed out"),
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
            format!("failed to inspect durable state after replacement KVM Delete: {error}"),
        ),
    }
    drop(service);
    report.replacement_vm = driver.shutdown().await;
    if let Err(reason) = driver.cleanup(&first.target).await {
        append_failure(&mut failure, reason);
    }
    match path_absent(&first.init_marker).await {
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
            format!("replacement KVM {label} init marker remained after cleanup"),
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut failure,
            format!("replacement KVM {label} owner left its runtime share"),
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut failure,
            format!("first and replacement KVM {label} owner identities were not distinct"),
        );
    }
    failure.map_or(Ok(()), Err)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MutationResponse {
    File(FileResponse),
    Filesystem(Box<FilesystemResponse>),
}

impl MutationResponse {
    fn target(&self) -> &ContainerTarget {
        match self {
            Self::File(response) => &response.target,
            Self::Filesystem(response) => &response.target,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MutationJournalStatus {
    Prepared,
    Succeeded(MutationResponse),
}

async fn dispatch_host_mutation(
    service: &HostRuntimeService,
    mutation: &Mutation,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => service
            .file(request.clone())
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => service
            .filesystem(request.clone())
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

async fn mutation_journal_status(
    state_root: &Path,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> Result<MutationJournalStatus, String> {
    match mutation {
        Mutation::File { request, .. } => {
            match file_mutation_journal_status(state_root, request, target).await? {
                FileMutationJournalStatus::Prepared => Ok(MutationJournalStatus::Prepared),
                FileMutationJournalStatus::Succeeded(response) => Ok(
                    MutationJournalStatus::Succeeded(MutationResponse::File(response)),
                ),
            }
        }
        Mutation::Filesystem { request, .. } => {
            match filesystem_mutation_journal_status(state_root, request, target).await? {
                FilesystemMutationJournalStatus::Prepared => Ok(MutationJournalStatus::Prepared),
                FilesystemMutationJournalStatus::Succeeded(response) => Ok(
                    MutationJournalStatus::Succeeded(MutationResponse::Filesystem(response)),
                ),
            }
        }
    }
}

fn response_matches(
    response: &MutationResponse,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> bool {
    match (response, mutation) {
        (
            MutationResponse::File(response),
            Mutation::File {
                expected_payload, ..
            },
        ) => upload_response_matches(response, target, expected_payload.len()),
        (MutationResponse::Filesystem(response), Mutation::Filesystem { request, .. }) => {
            directory_response_matches(response, target, &request.path)
        }
        _ => false,
    }
}

fn effect_matches(
    response: &MutationResponse,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> bool {
    match (response, mutation) {
        (
            MutationResponse::File(response),
            Mutation::File {
                request,
                expected_payload,
                ..
            },
        ) => request.data.as_deref().is_some_and(|encoded| {
            download_response_matches(response, target, encoded, expected_payload.len())
        }),
        (MutationResponse::Filesystem(response), Mutation::Filesystem { request, .. }) => {
            directory_response_matches(response, target, &request.path)
        }
        _ => false,
    }
}

fn response_generation(response: &MutationResponse) -> Option<Generation> {
    response.target().generation
}

fn mutation_calls(driver: &QualificationKvmOperationDriver, mutation: &Mutation) -> u32 {
    match mutation {
        Mutation::File { .. } => driver.file_calls(),
        Mutation::Filesystem { .. } => driver.filesystem_calls(),
    }
}

fn driver_mutation_identity(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
) -> Result<MutationIdentity, String> {
    match mutation {
        Mutation::File { .. } => driver.file_identity().map(MutationIdentity::File),
        Mutation::Filesystem { .. } => driver
            .filesystem_identity()
            .map(MutationIdentity::Filesystem),
    }
}

fn mutation_identity_operation_id(identity: &MutationIdentity) -> Option<&OperationId> {
    match identity {
        MutationIdentity::File(request) => request.context.as_ref(),
        MutationIdentity::Filesystem(request) => request.context.as_ref(),
    }
    .map(|context| &context.operation_id)
}

fn mutation_identity_target(identity: &MutationIdentity) -> &ContainerTarget {
    match identity {
        MutationIdentity::File(request) => &request.target,
        MutationIdentity::Filesystem(request) => &request.target,
    }
}

fn capture_recovery(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    report: &mut OciVmOperationReopenReplacementReport,
) {
    report.replacement_recovery_calls = driver.recovery_calls();
    report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
    report.replacement_rehydrated_running_record = driver.rehydrated_running_record();
    report.replacement_rehydrated_stopped_record = driver.rehydrated_stopped_record();
    report.replacement_rehydrated_exec_record = driver.rehydrated_exec_record();
    match mutation {
        Mutation::File { .. } => report.replacement_rehydrated_file = driver.rehydrated_file(),
        Mutation::Filesystem { .. } => {
            report.replacement_rehydrated_filesystem = driver.rehydrated_filesystem();
        }
    }
    report.replacement_created_pid = driver.rehydrated_running_pid();
    report.replacement_exec_pid = driver
        .rehydrated_exec_pid()
        .and_then(|pid| u32::try_from(pid).ok());
}

async fn direct_effect_query(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { download, .. } => driver
            .guest_file(FileRequest {
                target: target.clone(),
                ..download.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { stat, .. } => driver
            .guest_filesystem(FilesystemRequest {
                target: target.clone(),
                ..stat.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

async fn direct_effect_cleanup(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> a3s_oci_sdk::Result<FilesystemResponse> {
    let cleanup = match mutation {
        Mutation::File { cleanup, .. } | Mutation::Filesystem { cleanup, .. } => {
            FilesystemRequest {
                target: target.clone(),
                ..cleanup.clone()
            }
        }
    };
    driver.guest_filesystem(cleanup).await
}

async fn dispatch_changed_host_mutation(
    service: &HostRuntimeService,
    mutation: &Mutation,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => service
            .file(FileRequest {
                data: Some(changed_upload_data()),
                ..request.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => service
            .filesystem(FilesystemRequest {
                path: format!("{}-changed", request.path),
                ..request.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

async fn dispatch_stale_guest_mutation(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    target: ContainerTarget,
    operation_id: OperationId,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => driver
            .guest_file(FileRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => driver
            .guest_filesystem(FilesystemRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

async fn dispatch_stale_host_mutation(
    service: &HostRuntimeService,
    mutation: &Mutation,
    target: ContainerTarget,
    operation_id: OperationId,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => service
            .file(FileRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => service
            .filesystem(FilesystemRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

fn set_replacement_response_verified(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    verified: bool,
) {
    match mutation {
        Mutation::File { .. } => report.replacement_file_response_verified = verified,
        Mutation::Filesystem { .. } => report.replacement_filesystem_response_verified = verified,
    }
}

fn set_response_replayed(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    replayed: bool,
) {
    match mutation {
        Mutation::File { .. } => report.file_response_replayed = replayed,
        Mutation::Filesystem { .. } => report.filesystem_response_replayed = replayed,
    }
}

fn set_request_identity_reused(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    reused: bool,
) {
    match mutation {
        Mutation::File { .. } => report.file_request_identity_reused = reused,
        Mutation::Filesystem { .. } => report.filesystem_request_identity_reused = reused,
    }
}

fn set_effect_verified(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    verified: bool,
) {
    match mutation {
        Mutation::File { .. } => report.replacement_file_effect_verified = verified,
        Mutation::Filesystem { .. } => report.replacement_filesystem_effect_verified = verified,
    }
}

fn set_effect_absent(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    absent: bool,
) {
    match mutation {
        Mutation::File { .. } => report.file_effect_absent_after_cleanup = absent,
        Mutation::Filesystem { .. } => report.filesystem_effect_absent_after_cleanup = absent,
    }
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

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, FileOp, FileRequest, FilesystemOp, FilesystemRequest,
        Generation, OperationContext, OperationId,
    };

    use super::{
        mutation_identity_operation_id, mutation_identity_target, Mutation, MutationIdentity,
    };

    #[test]
    fn exact_mutation_identity_rebinds_only_the_target() {
        let current = ContainerTarget::current(ContainerId::new("test").expect("container ID"));
        let exact = ContainerTarget::exact(
            ContainerId::new("test").expect("container ID"),
            Generation(7),
        );
        let operation_id = OperationId::new("upload").expect("operation ID");
        let mutation = Mutation::File {
            request: FileRequest {
                target: current,
                op: FileOp::Upload,
                path: "/tmp/test".to_string(),
                data: Some("dGVzdA==".to_string()),
                user: None,
                context: Some(OperationContext::new(operation_id.clone())),
            },
            download: FileRequest {
                target: exact.clone(),
                op: FileOp::Download,
                path: "/tmp/test".to_string(),
                data: None,
                user: None,
                context: None,
            },
            cleanup: FilesystemRequest {
                target: exact.clone(),
                op: FilesystemOp::Remove,
                path: "/tmp/test".to_string(),
                destination: None,
                depth: 0,
                user: None,
                context: Some(OperationContext::new(
                    OperationId::new("cleanup").expect("operation ID"),
                )),
            },
            expected_payload: b"test".to_vec(),
        };
        let identity = mutation.exact_identity(&exact);
        assert_eq!(mutation_identity_target(&identity), &exact);
        assert_eq!(
            mutation_identity_operation_id(&identity),
            Some(&operation_id)
        );
        assert!(matches!(identity, MutationIdentity::File(_)));
    }
}
