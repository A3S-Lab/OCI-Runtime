use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, GuestAgentService,
    AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, HostPlatform, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, CloseStdinRequest, ContainerOperationRequest, ContainerRecord, ContainerStats,
    ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    ExecRequest, ExitStatus, FileRequest, FileResponse, IoMode, IsolationRequest, KillRequest,
    ListRequest, OciBundle, OciRuntimeService, OperationContext, OperationId, OutputChunk,
    ProcessIo, ProcessRecord, ProcessTarget, ResizeRequest, Result, RuntimeOperation,
    SignalProcessRequest, StartRequest, StateRequest, UpdateRequest, WriteStdinRequest,
};
use tokio::time::{sleep, timeout, Instant};

use super::transport_fault_cleanup::{read_guest_qualification_evidence, HostTransportFault};
use super::{
    canonical_directory, fixed_rootfs, guest_path, path_exists, read_marker, remove_marker,
    runtime_entries, target, unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use crate::agent_driver::AgentDriverClient;
use crate::agent_session::UtilityVmSession;
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateAttachments,
    DriverCreateRequest, DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, RuntimeDriver,
};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{AgentVmSmokeReport, DriverRecovery, OciVmReopenReplacementReport};

const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(15);
const FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";
const REPLACEMENT_MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
const MARKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const QUALIFICATION_HVF_OPERATIONS: [RuntimeOperation; 19] = [
    RuntimeOperation::Create,
    RuntimeOperation::State,
    RuntimeOperation::Start,
    RuntimeOperation::Kill,
    RuntimeOperation::Delete,
    RuntimeOperation::Wait,
    RuntimeOperation::Exec,
    RuntimeOperation::SignalProcess,
    RuntimeOperation::WaitProcess,
    RuntimeOperation::Pause,
    RuntimeOperation::Resume,
    RuntimeOperation::Processes,
    RuntimeOperation::Update,
    RuntimeOperation::Stats,
    RuntimeOperation::ReadOutput,
    RuntimeOperation::WriteStdin,
    RuntimeOperation::CloseStdin,
    RuntimeOperation::Resize,
    RuntimeOperation::File,
];

mod close_stdin;
pub(super) use close_stdin::run as run_close_stdin;
mod delete;
pub(super) use delete::run as run_delete;
mod delete_support;
mod exec;
pub(super) use exec::run as run_exec;
mod file;
pub(super) use file::run as run_file;
mod kill;
pub(super) use kill::run as run_kill;
mod pause;
pub(super) use pause::run as run_pause;
mod processes;
pub(super) use processes::run as run_processes;
mod read_output;
pub(super) use read_output::run as run_read_output;
mod resize;
pub(super) use resize::run as run_resize;
mod resume;
pub(super) use resume::run as run_resume;
mod signal_process;
pub(super) use signal_process::run as run_signal_process;
mod stats;
pub(super) use stats::run as run_stats;
mod state;
pub(super) use state::run as run_state;
mod start;
pub(super) use start::run as run_start;
mod update;
pub(super) use update::run as run_update;
mod wait;
pub(super) use wait::run as run_wait;
mod wait_process;
pub(super) use wait_process::run as run_wait_process;
mod write_stdin;
pub(super) use write_stdin::run as run_write_stdin;

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmReopenReplacementReport {
    let mut report = OciVmReopenReplacementReport::initial(HostPlatform::current(), stage);
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
                    "refusing to overwrite an existing reopen qualification marker: {}",
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
    let exact_target = match target(&format!("reopen-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let operation_id = match OperationId::new(format!("reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(error) => {
            return failed(
                report,
                format!("failed to construct reopen create operation ID: {error}"),
            );
        }
    };
    let delete_operation_id = match OperationId::new(format!("reopen-{nonce}-delete")) {
        Ok(operation_id) => operation_id,
        Err(error) => {
            return failed(
                report,
                format!("failed to construct reopen delete operation ID: {error}"),
            );
        }
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
                format!("failed to construct reopen create attachments: {error}"),
            );
        }
    };
    let request = CreateRequest {
        context: OperationContext::new(operation_id.clone()),
        id: exact_target.id.clone(),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments,
    };
    let guest_qualification = if stage.is_guest() {
        match AgentTransportQualificationRequest::new(
            operation_id.clone(),
            AgentOperation::Create,
            stage,
        ) {
            Ok(request) => Some(request),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to construct Guest reopen qualification: {error}"),
                );
            }
        }
    } else {
        None
    };
    report.qualification_operation_id = Some(operation_id);
    report.container_id = Some(exact_target.id.clone());

    let state_root = console_directory.join(format!("a3s-oci-reopen-{nonce}-state"));
    if let Err(reason) = create_qualification_state_root(&state_root).await {
        return failed(report, reason);
    }
    let first_console = console_directory.join(format!("a3s-oci-reopen-{nonce}-first.log"));
    let replacement_console =
        console_directory.join(format!("a3s-oci-reopen-{nonce}-replacement.log"));

    let exercise = exercise(
        shim,
        &vm_rootfs,
        &state_root,
        &first_console,
        &replacement_console,
        &request,
        &delete_operation_id,
        &baseline_runtime_entries,
        stage,
        guest_qualification.as_ref(),
        &mut report,
    )
    .await;

    match path_exists(&marker).await {
        Ok(false) => report.marker_absent_after_cleanup = true,
        Ok(true) => {
            append_reason(
                &mut report,
                format!(
                    "workload marker appeared during create-only reopen qualification: {}",
                    marker.display()
                ),
            );
            if let Err(reason) = remove_marker(&marker).await {
                append_reason(&mut report, reason);
            }
        }
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
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    request: &CreateRequest,
    delete_operation_id: &OperationId,
    baseline_runtime_entries: &std::collections::BTreeSet<String>,
    stage: AgentTransportOperationStage,
    guest_qualification: Option<&AgentTransportQualificationRequest>,
    report: &mut OciVmReopenReplacementReport,
) -> std::result::Result<(), String> {
    let faults = Arc::new(HostTransportFault::new(AgentTransportFaultStage::from(
        stage,
    )));
    let first_cleanup = MacosHostCleanupTracker::capture();
    let first_session_result = match guest_qualification {
        Some(qualification) => {
            UtilityVmSession::connect_with_guest_qualification(
                shim,
                vm_rootfs,
                first_console,
                qualification,
            )
            .await
        }
        None => {
            UtilityVmSession::connect_with_host_fault_injector(
                shim,
                vm_rootfs,
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
                .unwrap_or_else(|| "failed to launch the first qualification VM".to_string());
            report.first_vm = bridge;
            return Err(reason);
        }
    };
    let first_driver = Arc::new(QualificationHvfDriver::new(
        Arc::clone(&first_session),
        vm_rootfs.to_path_buf(),
        request.clone(),
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
                "failed to open the first durable host service: {error}"
            ));
        }
    };

    let response_delivered = matches!(stage, AgentTransportOperationStage::GuestAfterResponseWrite);
    let mut first_failure = None;
    match timeout(QUALIFICATION_TIMEOUT, first_service.create(request.clone())).await {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_first_interruption(report, error, stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Err(error)) => append_failure(
            &mut first_failure,
            format!(
                "{} did not deliver its completed Create response: {error}",
                stage.as_str()
            ),
        ),
        Ok(Ok(record)) if response_delivered => {
            report.first_create_response_received = true;
            if *record.state.status() != ContainerState::Created {
                append_failure(
                    &mut first_failure,
                    format!(
                        "{} returned {} instead of created",
                        stage.as_str(),
                        record.state.status()
                    ),
                );
            }
            report.disconnect_probe_attempted = true;
            let probe = StateRequest {
                target: ContainerTarget::exact(request.id.clone(), record.generation),
            };
            match timeout(QUALIFICATION_TIMEOUT, first_service.state(probe)).await {
                Ok(Err(error)) => {
                    if let Err(reason) = record_first_interruption(report, error, stage) {
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
        Ok(Ok(_)) => append_failure(
            &mut first_failure,
            "first create unexpectedly completed before owner replacement",
        ),
        Err(_) => append_failure(
            &mut first_failure,
            format!(
                "first create exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    match first_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_before_reopen = Some(record.generation);
            let exact_record = record.state.id() == request.id.as_str()
                && record.driver == DriverKind::LibkrunHvf
                && record.isolation == IsolationClass::DedicatedVm;
            report.durable_creating_retained =
                exact_record && *record.state.status() == ContainerState::Creating;
            report.durable_created_retained =
                exact_record && *record.state.status() == ContainerState::Created;
            if report.durable_created_retained {
                report.first_created_pid = *record.state.pid();
            }
            let expected_record_retained = if response_delivered {
                report.durable_created_retained
            } else {
                report.durable_creating_retained
            };
            if !expected_record_retained {
                append_failure(
                    &mut first_failure,
                    format!(
                        "interrupted create retained {} instead of the exact durable {} record",
                        record.state.status(),
                        if response_delivered {
                            "created"
                        } else {
                            "creating"
                        }
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut first_failure,
            format!(
                "interrupted create retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut first_failure,
            format!("failed to inspect the interrupted durable create: {error}"),
        ),
    }
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
                        "Guest reopen qualification evidence did not match the exact request",
                    );
                }
            }
            Err(reason) => append_failure(&mut first_failure, reason),
        }
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
    if report.fault_crossings != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "selected transport point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    if let Some(reason) = first_failure {
        return Err(reason);
    }
    let first_create_identity = first_driver.create_identity()?;
    drop(first_driver);
    drop(first_session);

    let replacement_cleanup = MacosHostCleanupTracker::capture();
    let replacement_session =
        match UtilityVmSession::connect(shim, vm_rootfs, replacement_console).await {
            Ok(session) => Arc::new(session),
            Err(mut bridge) => {
                replacement_cleanup.apply(&mut bridge).await;
                let reason = bridge.reason.clone().unwrap_or_else(|| {
                    "failed to launch the replacement qualification VM".to_string()
                });
                report.replacement_vm = bridge;
                return Err(reason);
            }
        };
    let replacement_driver = Arc::new(QualificationHvfDriver::new(
        Arc::clone(&replacement_session),
        vm_rootfs.to_path_buf(),
        request.clone(),
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
            service
        }
        Err(error) => {
            report.replacement_recovery_calls = replacement_driver.recovery_calls();
            report.replacement_rehydrated_created_record =
                replacement_driver.rehydrated_created_record();
            report.replacement_vm = replacement_driver.shutdown().await;
            replacement_cleanup.apply(&mut report.replacement_vm).await;
            return Err(format!(
                "failed to reopen durable host service around the replacement VM: {error}"
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
    match timeout(
        QUALIFICATION_TIMEOUT,
        replacement_service.create(request.clone()),
    )
    .await
    {
        Ok(Ok(record)) => {
            report.generation_after_reopen = Some(record.generation);
            report.replacement_created_pid = *record.state.pid();
            report.create_completed_after_reopen =
                *record.state.status() == ContainerState::Created;
            match replacement_driver.create_identity() {
                Ok(replacement_create_identity) => {
                    report.same_generation_reused = report.generation_before_reopen
                        == Some(record.generation)
                        && first_create_identity.1 == replacement_create_identity.1
                        && replacement_create_identity.1.generation == Some(record.generation);
                    report.same_operation_id_reused = first_create_identity.0
                        == replacement_create_identity.0
                        && replacement_create_identity.0 == request.context.operation_id;
                }
                Err(reason) => append_failure(&mut replacement_failure, reason),
            }
            if !report.create_completed_after_reopen {
                append_failure(
                    &mut replacement_failure,
                    "replacement create did not reach the OCI created state",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement create did not reuse the original durable generation",
                );
            }
            if !report.same_operation_id_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement create did not reuse the original OperationId",
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("replacement create failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement create exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }

    if let Some(generation) = report.generation_before_reopen {
        let delete = DeleteRequest {
            context: OperationContext::new(delete_operation_id.clone()),
            target: ContainerTarget::exact(request.id.clone(), generation),
            mode: DeleteMode::Force,
        };
        match timeout(QUALIFICATION_TIMEOUT, replacement_service.delete(delete)).await {
            Ok(Ok(())) => report.force_delete_completed = true,
            Ok(Err(error)) => append_failure(
                &mut replacement_failure,
                format!("replacement force delete failed: {error}"),
            ),
            Err(_) => append_failure(
                &mut replacement_failure,
                format!(
                    "replacement force delete exceeded the {} second timeout",
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

struct QualificationHvfDriver {
    client: AgentDriverClient,
    session: Arc<UtilityVmSession>,
    vm_rootfs: PathBuf,
    recovery_create: CreateRequest,
    recovery_start: Option<StartRequest>,
    recovery_kill: Option<KillRequest>,
    recovery_exec: Option<ExecRequest>,
    recovery_signal_process: Option<SignalProcessRequest>,
    recovery_signal_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_write_stdin: Option<WriteStdinRequest>,
    recovery_write_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_close_stdin: Option<CloseStdinRequest>,
    recovery_close_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_resize: Option<ResizeRequest>,
    recovery_resize_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_file: Option<FileRequest>,
    recovery_file_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_pause: Option<ContainerOperationRequest>,
    recovery_pause_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_resume: Option<ContainerOperationRequest>,
    recovery_update: Option<UpdateRequest>,
    recovery_update_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_exec_is_live: bool,
    recovery_marker: Option<PathBuf>,
    recovery_calls: AtomicU32,
    rehydrated_created_record: AtomicBool,
    rehydrated_running_record: AtomicBool,
    rehydrated_stopped_record: AtomicBool,
    rehydrated_exec_record: AtomicBool,
    rehydrated_signal_process: AtomicBool,
    rehydrated_write_stdin: AtomicBool,
    rehydrated_close_stdin: AtomicBool,
    rehydrated_resize: AtomicBool,
    rehydrated_file: AtomicBool,
    rehydrated_paused_record: AtomicBool,
    rehydrated_resumed_record: AtomicBool,
    rehydrated_update: AtomicBool,
    rehydrated_running_pid: AtomicI32,
    rehydrated_exec_pid: AtomicI32,
    create_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    start_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    kill_identity: StdMutex<Option<(OperationId, ContainerTarget, a3s_oci_sdk::Signal, bool)>>,
    delete_identity: StdMutex<Option<(OperationId, ContainerTarget, DeleteMode)>>,
    wait_identity: StdMutex<Option<(ContainerTarget, Option<u64>)>>,
    wait_process_identity: StdMutex<Option<(ProcessTarget, Option<u64>)>>,
    exec_identity: StdMutex<Option<DriverExecRequest>>,
    signal_process_identity: StdMutex<Option<DriverSignalProcessRequest>>,
    write_stdin_identity: StdMutex<Option<DriverWriteStdinRequest>>,
    close_stdin_identity: StdMutex<Option<DriverCloseStdinRequest>>,
    resize_identity: StdMutex<Option<DriverResizeRequest>>,
    file_identity: StdMutex<Option<FileRequest>>,
    pause_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    resume_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    processes_identity: StdMutex<Option<ContainerTarget>>,
    update_identity: StdMutex<Option<DriverUpdateRequest>>,
    stats_identity: StdMutex<Option<ContainerTarget>>,
    read_output_identity: StdMutex<Option<DriverReadOutputRequest>>,
    start_calls: AtomicU32,
    kill_calls: AtomicU32,
    delete_calls: AtomicU32,
    wait_calls: AtomicU32,
    wait_process_calls: AtomicU32,
    exec_calls: AtomicU32,
    signal_process_calls: AtomicU32,
    write_stdin_calls: AtomicU32,
    close_stdin_calls: AtomicU32,
    resize_calls: AtomicU32,
    file_calls: AtomicU32,
    pause_calls: AtomicU32,
    resume_calls: AtomicU32,
    processes_calls: AtomicU32,
    update_calls: AtomicU32,
    stats_calls: AtomicU32,
    read_output_calls: AtomicU32,
}

struct WaitProcessRecovery {
    signal_process: SignalProcessRequest,
    signal_ready_marker: (PathBuf, Vec<u8>),
    exec_is_live: bool,
}

impl QualificationHvfDriver {
    fn new(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
    ) -> Self {
        Self::with_recovery_operations(session, vm_rootfs, recovery_create, None, None, None, None)
    }

    fn with_start_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
    ) -> Self {
        Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            None,
        )
    }

    fn with_kill_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_kill: KillRequest,
        recovery_marker: PathBuf,
    ) -> Self {
        Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            Some(recovery_kill),
            Some(recovery_marker),
            None,
        )
    }

    fn with_delete_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_kill: KillRequest,
        recovery_marker: PathBuf,
    ) -> Self {
        Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            Some(recovery_kill),
            Some(recovery_marker),
            None,
        )
    }

    fn with_exec_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_exec: Option<ExecRequest>,
    ) -> Self {
        Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            recovery_exec,
        )
    }

    fn with_signal_process_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_exec: ExecRequest,
        recovery_signal_process: Option<SignalProcessRequest>,
        recovery_signal_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            Some(recovery_exec),
        );
        driver.recovery_signal_process = recovery_signal_process;
        driver.recovery_signal_ready_marker = recovery_signal_ready_marker;
        driver
    }

    fn with_write_stdin_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_exec: ExecRequest,
        recovery_write_stdin: Option<WriteStdinRequest>,
        recovery_write_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            Some(recovery_exec),
        );
        driver.recovery_write_stdin = recovery_write_stdin;
        driver.recovery_write_ready_marker = recovery_write_ready_marker;
        driver
    }

    fn with_close_stdin_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_exec: ExecRequest,
        recovery_close_stdin: Option<CloseStdinRequest>,
        recovery_close_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            Some(recovery_exec),
        );
        driver.recovery_close_stdin = recovery_close_stdin;
        driver.recovery_close_ready_marker = recovery_close_ready_marker;
        driver
    }

    fn with_resize_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_exec: ExecRequest,
        recovery_resize: Option<ResizeRequest>,
        recovery_resize_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            Some(recovery_exec),
        );
        driver.recovery_resize = recovery_resize;
        driver.recovery_resize_ready_marker = recovery_resize_ready_marker;
        driver
    }

    fn with_file_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_file: Option<FileRequest>,
        recovery_file_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            None,
        );
        driver.recovery_file = recovery_file;
        driver.recovery_file_ready_marker = recovery_file_ready_marker;
        driver
    }

    fn with_pause_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_pause: Option<ContainerOperationRequest>,
        recovery_pause_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            None,
        );
        driver.recovery_pause = recovery_pause;
        driver.recovery_pause_ready_marker = recovery_pause_ready_marker;
        driver
    }

    fn with_resume_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_pause: ContainerOperationRequest,
        recovery_pause_ready_marker: (PathBuf, Vec<u8>),
        recovery_resume: Option<ContainerOperationRequest>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            None,
        );
        driver.recovery_pause = Some(recovery_pause);
        driver.recovery_pause_ready_marker = Some(recovery_pause_ready_marker);
        driver.recovery_resume = recovery_resume;
        driver
    }

    fn with_update_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_update: Option<UpdateRequest>,
        recovery_update_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            None,
        );
        driver.recovery_update = recovery_update;
        driver.recovery_update_ready_marker = recovery_update_ready_marker;
        driver
    }

    fn with_wait_process_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
        recovery_exec: ExecRequest,
        recovery: WaitProcessRecovery,
    ) -> Self {
        let mut driver = Self::with_recovery_operations(
            session,
            vm_rootfs,
            recovery_create,
            Some(recovery_start),
            None,
            None,
            Some(recovery_exec),
        );
        driver.recovery_signal_process = Some(recovery.signal_process);
        driver.recovery_signal_ready_marker = Some(recovery.signal_ready_marker);
        driver.recovery_exec_is_live = recovery.exec_is_live;
        driver
    }

    fn with_recovery_operations(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: Option<StartRequest>,
        recovery_kill: Option<KillRequest>,
        recovery_marker: Option<PathBuf>,
        recovery_exec: Option<ExecRequest>,
    ) -> Self {
        let service: Arc<dyn GuestAgentService> = Arc::new(session.client());
        Self {
            client: AgentDriverClient::new(
                service,
                "qualification-only HVF guest agent",
                "qualification-hvf",
            ),
            session,
            vm_rootfs,
            recovery_create,
            recovery_start,
            recovery_kill,
            recovery_marker,
            recovery_exec,
            recovery_signal_process: None,
            recovery_signal_ready_marker: None,
            recovery_write_stdin: None,
            recovery_write_ready_marker: None,
            recovery_close_stdin: None,
            recovery_close_ready_marker: None,
            recovery_resize: None,
            recovery_resize_ready_marker: None,
            recovery_file: None,
            recovery_file_ready_marker: None,
            recovery_pause: None,
            recovery_pause_ready_marker: None,
            recovery_resume: None,
            recovery_update: None,
            recovery_update_ready_marker: None,
            recovery_exec_is_live: true,
            recovery_calls: AtomicU32::new(0),
            rehydrated_created_record: AtomicBool::new(false),
            rehydrated_running_record: AtomicBool::new(false),
            rehydrated_stopped_record: AtomicBool::new(false),
            rehydrated_exec_record: AtomicBool::new(false),
            rehydrated_signal_process: AtomicBool::new(false),
            rehydrated_write_stdin: AtomicBool::new(false),
            rehydrated_close_stdin: AtomicBool::new(false),
            rehydrated_resize: AtomicBool::new(false),
            rehydrated_file: AtomicBool::new(false),
            rehydrated_paused_record: AtomicBool::new(false),
            rehydrated_resumed_record: AtomicBool::new(false),
            rehydrated_update: AtomicBool::new(false),
            rehydrated_running_pid: AtomicI32::new(0),
            rehydrated_exec_pid: AtomicI32::new(0),
            create_identity: StdMutex::new(None),
            start_identity: StdMutex::new(None),
            kill_identity: StdMutex::new(None),
            delete_identity: StdMutex::new(None),
            wait_identity: StdMutex::new(None),
            wait_process_identity: StdMutex::new(None),
            exec_identity: StdMutex::new(None),
            signal_process_identity: StdMutex::new(None),
            write_stdin_identity: StdMutex::new(None),
            close_stdin_identity: StdMutex::new(None),
            resize_identity: StdMutex::new(None),
            file_identity: StdMutex::new(None),
            pause_identity: StdMutex::new(None),
            resume_identity: StdMutex::new(None),
            processes_identity: StdMutex::new(None),
            update_identity: StdMutex::new(None),
            stats_identity: StdMutex::new(None),
            read_output_identity: StdMutex::new(None),
            start_calls: AtomicU32::new(0),
            kill_calls: AtomicU32::new(0),
            delete_calls: AtomicU32::new(0),
            wait_calls: AtomicU32::new(0),
            wait_process_calls: AtomicU32::new(0),
            exec_calls: AtomicU32::new(0),
            signal_process_calls: AtomicU32::new(0),
            write_stdin_calls: AtomicU32::new(0),
            close_stdin_calls: AtomicU32::new(0),
            resize_calls: AtomicU32::new(0),
            file_calls: AtomicU32::new(0),
            pause_calls: AtomicU32::new(0),
            resume_calls: AtomicU32::new(0),
            processes_calls: AtomicU32::new(0),
            update_calls: AtomicU32::new(0),
            stats_calls: AtomicU32::new(0),
            read_output_calls: AtomicU32::new(0),
        }
    }

    fn recovery_calls(&self) -> u32 {
        self.recovery_calls.load(Ordering::SeqCst)
    }

    fn rehydrated_created_record(&self) -> bool {
        self.rehydrated_created_record.load(Ordering::SeqCst)
    }

    fn rehydrated_running_record(&self) -> bool {
        self.rehydrated_running_record.load(Ordering::SeqCst)
    }

    fn rehydrated_stopped_record(&self) -> bool {
        self.rehydrated_stopped_record.load(Ordering::SeqCst)
    }

    fn rehydrated_exec_record(&self) -> bool {
        self.rehydrated_exec_record.load(Ordering::SeqCst)
    }

    fn rehydrated_signal_process(&self) -> bool {
        self.rehydrated_signal_process.load(Ordering::SeqCst)
    }

    fn rehydrated_write_stdin(&self) -> bool {
        self.rehydrated_write_stdin.load(Ordering::SeqCst)
    }

    fn rehydrated_close_stdin(&self) -> bool {
        self.rehydrated_close_stdin.load(Ordering::SeqCst)
    }

    fn rehydrated_resize(&self) -> bool {
        self.rehydrated_resize.load(Ordering::SeqCst)
    }

    fn rehydrated_file(&self) -> bool {
        self.rehydrated_file.load(Ordering::SeqCst)
    }

    fn rehydrated_paused_record(&self) -> bool {
        self.rehydrated_paused_record.load(Ordering::SeqCst)
    }

    fn rehydrated_resumed_record(&self) -> bool {
        self.rehydrated_resumed_record.load(Ordering::SeqCst)
    }

    fn rehydrated_update(&self) -> bool {
        self.rehydrated_update.load(Ordering::SeqCst)
    }

    fn rehydrated_running_pid(&self) -> Option<i32> {
        match self.rehydrated_running_pid.load(Ordering::SeqCst) {
            pid if pid > 0 => Some(pid),
            _ => None,
        }
    }

    fn rehydrated_exec_pid(&self) -> Option<i32> {
        match self.rehydrated_exec_pid.load(Ordering::SeqCst) {
            pid if pid > 0 => Some(pid),
            _ => None,
        }
    }

    fn start_calls(&self) -> u32 {
        self.start_calls.load(Ordering::SeqCst)
    }

    fn kill_calls(&self) -> u32 {
        self.kill_calls.load(Ordering::SeqCst)
    }

    fn delete_calls(&self) -> u32 {
        self.delete_calls.load(Ordering::SeqCst)
    }

    fn wait_calls(&self) -> u32 {
        self.wait_calls.load(Ordering::SeqCst)
    }

    fn wait_process_calls(&self) -> u32 {
        self.wait_process_calls.load(Ordering::SeqCst)
    }

    fn exec_calls(&self) -> u32 {
        self.exec_calls.load(Ordering::SeqCst)
    }

    fn signal_process_calls(&self) -> u32 {
        self.signal_process_calls.load(Ordering::SeqCst)
    }

    fn write_stdin_calls(&self) -> u32 {
        self.write_stdin_calls.load(Ordering::SeqCst)
    }

    fn close_stdin_calls(&self) -> u32 {
        self.close_stdin_calls.load(Ordering::SeqCst)
    }

    fn resize_calls(&self) -> u32 {
        self.resize_calls.load(Ordering::SeqCst)
    }

    fn file_calls(&self) -> u32 {
        self.file_calls.load(Ordering::SeqCst)
    }

    fn pause_calls(&self) -> u32 {
        self.pause_calls.load(Ordering::SeqCst)
    }

    fn resume_calls(&self) -> u32 {
        self.resume_calls.load(Ordering::SeqCst)
    }

    fn processes_calls(&self) -> u32 {
        self.processes_calls.load(Ordering::SeqCst)
    }

    fn update_calls(&self) -> u32 {
        self.update_calls.load(Ordering::SeqCst)
    }

    fn stats_calls(&self) -> u32 {
        self.stats_calls.load(Ordering::SeqCst)
    }

    fn read_output_calls(&self) -> u32 {
        self.read_output_calls.load(Ordering::SeqCst)
    }

    async fn shutdown(&self) -> AgentVmSmokeReport {
        self.session.shutdown().await
    }

    fn create_identity(&self) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.create_identity
            .lock()
            .map_err(|_| "qualification HVF create-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no create dispatch".to_string())
    }

    fn start_identity(&self) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.start_identity
            .lock()
            .map_err(|_| "qualification HVF start-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no start dispatch".to_string())
    }

    fn kill_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget, a3s_oci_sdk::Signal, bool), String>
    {
        self.kill_identity
            .lock()
            .map_err(|_| "qualification HVF kill-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no kill dispatch".to_string())
    }

    fn delete_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget, DeleteMode), String> {
        self.delete_identity
            .lock()
            .map_err(|_| "qualification HVF delete-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no delete dispatch".to_string())
    }

    fn wait_identity(&self) -> std::result::Result<(ContainerTarget, Option<u64>), String> {
        self.wait_identity
            .lock()
            .map_err(|_| "qualification HVF wait-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no wait dispatch".to_string())
    }

    fn wait_process_identity(&self) -> std::result::Result<(ProcessTarget, Option<u64>), String> {
        self.wait_process_identity
            .lock()
            .map_err(|_| "qualification HVF wait-process-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no WaitProcess dispatch".to_string())
    }

    fn exec_identity(&self) -> std::result::Result<DriverExecRequest, String> {
        self.exec_identity
            .lock()
            .map_err(|_| "qualification HVF exec-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no exec dispatch".to_string())
    }

    fn signal_process_identity(&self) -> std::result::Result<DriverSignalProcessRequest, String> {
        self.signal_process_identity
            .lock()
            .map_err(|_| "qualification HVF signal-process-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| {
                "qualification HVF driver recorded no SignalProcess dispatch".to_string()
            })
    }

    fn write_stdin_identity(&self) -> std::result::Result<DriverWriteStdinRequest, String> {
        self.write_stdin_identity
            .lock()
            .map_err(|_| "qualification HVF write-stdin-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no WriteStdin dispatch".to_string())
    }

    fn close_stdin_identity(&self) -> std::result::Result<DriverCloseStdinRequest, String> {
        self.close_stdin_identity
            .lock()
            .map_err(|_| "qualification HVF close-stdin-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no CloseStdin dispatch".to_string())
    }

    fn resize_identity(&self) -> std::result::Result<DriverResizeRequest, String> {
        self.resize_identity
            .lock()
            .map_err(|_| "qualification HVF resize-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no Resize dispatch".to_string())
    }

    fn file_identity(&self) -> std::result::Result<FileRequest, String> {
        self.file_identity
            .lock()
            .map_err(|_| "qualification HVF file-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no File dispatch".to_string())
    }

    fn pause_identity(&self) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.pause_identity
            .lock()
            .map_err(|_| "qualification HVF pause-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no Pause dispatch".to_string())
    }

    fn resume_identity(&self) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.resume_identity
            .lock()
            .map_err(|_| "qualification HVF resume-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no Resume dispatch".to_string())
    }

    fn processes_identity(&self) -> std::result::Result<ContainerTarget, String> {
        self.processes_identity
            .lock()
            .map_err(|_| "qualification HVF processes-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no Processes dispatch".to_string())
    }

    fn update_identity(&self) -> std::result::Result<DriverUpdateRequest, String> {
        self.update_identity
            .lock()
            .map_err(|_| "qualification HVF update-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no Update dispatch".to_string())
    }

    fn stats_identity(&self) -> std::result::Result<ContainerTarget, String> {
        self.stats_identity
            .lock()
            .map_err(|_| "qualification HVF stats-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no Stats dispatch".to_string())
    }

    fn read_output_identity(&self) -> std::result::Result<DriverReadOutputRequest, String> {
        self.read_output_identity
            .lock()
            .map_err(|_| "qualification HVF read-output-identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification HVF driver recorded no ReadOutput dispatch".to_string())
    }

    fn guest_bundle(&self, bundle: &OciBundle) -> Result<a3s_oci_agent_protocol::GuestPath> {
        guest_path(&self.vm_rootfs, bundle.directory()).map_err(|reason| {
            Error::new(ErrorCode::FailedPrecondition, reason)
                .for_operation("map-qualification-hvf-bundle")
        })
    }

    fn recovery_driver_request(&self, record: &ContainerRecord) -> Result<DriverCreateRequest> {
        let attachments_digest = self.recovery_create.attachments.digest()?;
        if record.state.id() != self.recovery_create.id.as_str()
            || record.driver != DriverKind::LibkrunHvf
            || record.isolation != self.recovery_create.isolation.class()
            || record.config_digest != self.recovery_create.bundle.config_digest()
            || record.attachments_digest.as_deref() != Some(attachments_digest.as_str())
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery record differs from the original Create request",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverCreateRequest {
            context: self.recovery_create.context.clone(),
            target: ContainerTarget::exact(self.recovery_create.id.clone(), record.generation),
            bundle: self.recovery_create.bundle.clone(),
            isolation: self.recovery_create.isolation.clone(),
            io: self.recovery_create.attachments.process_io().clone(),
            attachment_contract: self.recovery_create.attachments.clone(),
            attachments: DriverCreateAttachments::None,
        })
    }

    fn recovery_start_request(&self, record: &ContainerRecord) -> Result<DriverStartRequest> {
        let request = self.recovery_start.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained Start request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.recovery_create.id {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery Start target differs from the durable record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverStartRequest {
            context: request.context.clone(),
            target: exact_target,
            bundle: self.recovery_create.bundle.clone(),
        })
    }

    fn recovery_kill_request(&self, record: &ContainerRecord) -> Result<DriverKillRequest> {
        let request = self.recovery_kill.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained Kill request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.recovery_create.id {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery Kill target differs from the durable record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverKillRequest {
            context: request.context.clone(),
            target: exact_target,
            signal: request.signal,
            all: request.all,
        })
    }

    fn recovery_exec_request(&self, record: &ContainerRecord) -> Result<DriverExecRequest> {
        let request = self.recovery_exec.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained Exec request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_container =
            ContainerTarget::exact(request.container.id.clone(), record.generation);
        if request.container != exact_container || request.container.id != self.recovery_create.id {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery Exec target differs from the durable record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverExecRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process_id.clone(),
            },
            process: request.process.clone(),
            io: request.io.clone(),
        })
    }

    fn recovery_signal_process_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverSignalProcessRequest> {
        let request = self.recovery_signal_process.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained SignalProcess request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_container =
            ContainerTarget::exact(request.process.container.id.clone(), record.generation);
        let expected_process_id = self
            .recovery_exec
            .as_ref()
            .map(|exec| &exec.process_id)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::FailedPrecondition,
                    "qualification HVF SignalProcess recovery has no retained Exec request",
                )
                .for_operation("recover-qualification-hvf")
            })?;
        if request.process.container != exact_container
            || request.process.container.id != self.recovery_create.id
            || &request.process.process_id != expected_process_id
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery SignalProcess target differs from the durable Exec process",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverSignalProcessRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process.process_id.clone(),
            },
            signal: request.signal,
        })
    }

    fn recovery_write_stdin_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverWriteStdinRequest> {
        let request = self.recovery_write_stdin.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained WriteStdin request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_container =
            ContainerTarget::exact(request.process.container.id.clone(), record.generation);
        let expected_process_id = self
            .recovery_exec
            .as_ref()
            .map(|exec| &exec.process_id)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::FailedPrecondition,
                    "qualification HVF WriteStdin recovery has no retained Exec request",
                )
                .for_operation("recover-qualification-hvf")
            })?;
        if request.process.container != exact_container
            || request.process.container.id != self.recovery_create.id
            || &request.process.process_id != expected_process_id
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery WriteStdin target differs from the durable Exec process",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverWriteStdinRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process.process_id.clone(),
            },
            data: request.data.clone(),
        })
    }

    fn recovery_close_stdin_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverCloseStdinRequest> {
        let request = self.recovery_close_stdin.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained CloseStdin request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_container =
            ContainerTarget::exact(request.process.container.id.clone(), record.generation);
        let expected_process_id = self
            .recovery_exec
            .as_ref()
            .map(|exec| &exec.process_id)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::FailedPrecondition,
                    "qualification HVF CloseStdin recovery has no retained Exec request",
                )
                .for_operation("recover-qualification-hvf")
            })?;
        if request.process.container != exact_container
            || request.process.container.id != self.recovery_create.id
            || &request.process.process_id != expected_process_id
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery CloseStdin target differs from the durable Exec process",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverCloseStdinRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process.process_id.clone(),
            },
        })
    }

    fn recovery_resize_request(&self, record: &ContainerRecord) -> Result<DriverResizeRequest> {
        let request = self.recovery_resize.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained Resize request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_container =
            ContainerTarget::exact(request.process.container.id.clone(), record.generation);
        let expected_process_id = self
            .recovery_exec
            .as_ref()
            .map(|exec| &exec.process_id)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::FailedPrecondition,
                    "qualification HVF Resize recovery has no retained Exec request",
                )
                .for_operation("recover-qualification-hvf")
            })?;
        if request.process.container != exact_container
            || request.process.container.id != self.recovery_create.id
            || &request.process.process_id != expected_process_id
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery Resize target differs from the durable Exec process",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverResizeRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process.process_id.clone(),
            },
            size: request.size,
        })
    }

    fn recovery_file_request(&self, record: &ContainerRecord) -> Result<FileRequest> {
        let request = self.recovery_file.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained File request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        if request.target.id != self.recovery_create.id || request.context.is_none() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery File request differs from the durable container",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(FileRequest {
            target: ContainerTarget::exact(request.target.id.clone(), record.generation),
            ..request.clone()
        })
    }

    fn recovery_pause_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverContainerOperationRequest> {
        let request = self.recovery_pause.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained Pause request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.recovery_create.id {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery Pause target differs from the durable record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverContainerOperationRequest {
            context: request.context.clone(),
            target: exact_target,
        })
    }

    fn recovery_resume_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverContainerOperationRequest> {
        let request = self.recovery_resume.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained Resume request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.recovery_create.id {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery Resume target differs from the durable record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverContainerOperationRequest {
            context: request.context.clone(),
            target: exact_target,
        })
    }

    fn recovery_update_request(&self, record: &ContainerRecord) -> Result<DriverUpdateRequest> {
        let request = self.recovery_update.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement has no retained Update request",
            )
            .for_operation("recover-qualification-hvf")
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.recovery_create.id {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF recovery Update target differs from the durable record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        Ok(DriverUpdateRequest {
            context: request.context.clone(),
            target: exact_target,
            resources: request.resources.clone(),
        })
    }

    async fn dispatch_create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.create_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF create-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-create")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed create identity",
                    )
                    .for_operation("qualification-hvf-create"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        let guest_bundle = self.guest_bundle(&request.bundle)?;
        self.client.create(request, guest_bundle).await
    }

    async fn dispatch_start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.start_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF start-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-start")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed start identity",
                    )
                    .for_operation("qualification-hvf-start"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        self.client.start(request).await
    }

    async fn dispatch_kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let identity = (
            request.context.operation_id.clone(),
            request.target.clone(),
            request.signal,
            request.all,
        );
        {
            let mut retained = self.kill_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF kill-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-kill")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed kill identity",
                    )
                    .for_operation("qualification-hvf-kill"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.kill_calls.fetch_add(1, Ordering::SeqCst);
        self.client.kill(request).await
    }

    async fn dispatch_delete(&self, request: DriverDeleteRequest) -> Result<()> {
        let identity = (
            request.context.operation_id.clone(),
            request.target.clone(),
            request.mode,
        );
        {
            let mut retained = self.delete_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF delete-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-delete")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed delete identity",
                    )
                    .for_operation("qualification-hvf-delete"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.client.delete(request).await
    }

    async fn dispatch_wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        let identity = (request.target.clone(), request.timeout_ms);
        {
            let mut retained = self.wait_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF wait-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-wait")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed wait identity",
                    )
                    .for_operation("qualification-hvf-wait"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.wait_calls.fetch_add(1, Ordering::SeqCst);
        self.client.wait(request).await
    }

    async fn dispatch_exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        {
            let mut retained = self.exec_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF exec-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-exec")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed exec request",
                    )
                    .for_operation("qualification-hvf-exec"));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.exec_calls.fetch_add(1, Ordering::SeqCst);
        self.client.exec(request).await
    }

    async fn dispatch_signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        {
            let mut retained = self.signal_process_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF signal-process-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-signal-process")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed SignalProcess request",
                    )
                    .for_operation("qualification-hvf-signal-process"));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.signal_process_calls.fetch_add(1, Ordering::SeqCst);
        self.client.signal_process(request).await
    }

    async fn dispatch_write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        {
            let mut retained = self.write_stdin_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF write-stdin-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-write-stdin")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed WriteStdin request",
                    )
                    .for_operation("qualification-hvf-write-stdin"));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.write_stdin_calls.fetch_add(1, Ordering::SeqCst);
        self.client.write_stdin(request).await
    }

    async fn dispatch_close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        {
            let mut retained = self.close_stdin_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF close-stdin-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-close-stdin")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed CloseStdin request",
                    )
                    .for_operation("qualification-hvf-close-stdin"));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.close_stdin_calls.fetch_add(1, Ordering::SeqCst);
        self.client.close_stdin(request).await
    }

    async fn dispatch_resize(&self, request: DriverResizeRequest) -> Result<()> {
        {
            let mut retained = self.resize_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF resize-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-resize")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed Resize request",
                    )
                    .for_operation("qualification-hvf-resize"));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.resize_calls.fetch_add(1, Ordering::SeqCst);
        self.client.resize(request).await
    }

    async fn dispatch_file(&self, request: FileRequest) -> Result<FileResponse> {
        {
            let mut retained = self.file_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF file-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-file")
            })?;
            if retained.is_none() {
                *retained = Some(request.clone());
            }
        }
        self.file_calls.fetch_add(1, Ordering::SeqCst);
        self.client.file(request).await
    }

    async fn dispatch_pause(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.pause_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF pause-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-pause")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed Pause identity",
                    )
                    .for_operation("qualification-hvf-pause"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.pause_calls.fetch_add(1, Ordering::SeqCst);
        self.client.pause(request).await
    }

    async fn dispatch_resume(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.resume_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF resume-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-resume")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed Resume identity",
                    )
                    .for_operation("qualification-hvf-resume"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.resume_calls.fetch_add(1, Ordering::SeqCst);
        self.client.resume(request).await
    }

    async fn dispatch_processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        {
            let mut retained = self.processes_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF processes-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-processes")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &target => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed Processes target",
                    )
                    .for_operation("qualification-hvf-processes"));
                }
                Some(_) => {}
                None => *retained = Some(target.clone()),
            }
        }
        self.processes_calls.fetch_add(1, Ordering::SeqCst);
        self.client.processes(target).await
    }

    async fn dispatch_update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        {
            let mut retained = self.update_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF update-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-update")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed Update request",
                    )
                    .for_operation("qualification-hvf-update"));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.update_calls.fetch_add(1, Ordering::SeqCst);
        self.client.update(request).await
    }

    async fn dispatch_stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        {
            let mut retained = self.stats_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF stats-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-stats")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &target => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed Stats target",
                    )
                    .for_operation("qualification-hvf-stats"));
                }
                Some(_) => {}
                None => *retained = Some(target.clone()),
            }
        }
        self.stats_calls.fetch_add(1, Ordering::SeqCst);
        self.client.stats(target).await
    }

    async fn dispatch_read_output(
        &self,
        request: DriverReadOutputRequest,
    ) -> Result<Vec<OutputChunk>> {
        {
            let mut retained = self.read_output_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF read-output-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-read-output")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed ReadOutput request",
                    )
                    .for_operation("qualification-hvf-read-output"));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.read_output_calls.fetch_add(1, Ordering::SeqCst);
        self.client.read_output(request).await
    }

    async fn dispatch_wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        let identity = (request.target.clone(), request.timeout_ms);
        {
            let mut retained = self.wait_process_identity.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "qualification HVF wait-process-identity lock was poisoned",
                )
                .for_operation("qualification-hvf-wait-process")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "qualification HVF driver received a changed WaitProcess request",
                    )
                    .for_operation("qualification-hvf-wait-process"));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.wait_process_calls.fetch_add(1, Ordering::SeqCst);
        self.client.wait_process(request).await
    }
}

#[async_trait]
impl RuntimeDriver for QualificationHvfDriver {
    fn capability(&self) -> DriverCapability {
        DriverCapability {
            driver: DriverKind::LibkrunHvf,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::Experimental,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: None,
            evidence: BTreeMap::from([
                (
                    "execution_path".to_string(),
                    "real-hvf-utility-vm".to_string(),
                ),
                ("qualification_only".to_string(), "true".to_string()),
            ]),
        }
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &QUALIFICATION_HVF_OPERATIONS
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<DriverRecovery> {
        let recovery_state_supported = matches!(
            record.state.status(),
            ContainerState::Creating | ContainerState::Created
        ) || (*record.state.status() == ContainerState::Running
            && self.recovery_start.is_some())
            || (*record.state.status() == ContainerState::Stopped
                && self.recovery_start.is_some()
                && self.recovery_kill.is_some());
        if record.driver != DriverKind::LibkrunHvf
            || record.isolation != IsolationClass::DedicatedVm
            || !recovery_state_supported
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement accepts only its interrupted Create, Start, Kill, Delete, Wait, Exec, SignalProcess, WaitProcess, Pause, Resume, or Update record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        let freezer_recovery_matches = match (
            self.recovery_pause.is_some(),
            self.recovery_resume.is_some(),
        ) {
            (false, false) => !record.is_paused(),
            (true, false) => record.is_paused(),
            (true, true) => !record.is_paused(),
            (false, true) => false,
        };
        if *record.state.status() == ContainerState::Running && !freezer_recovery_matches {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF Pause/Resume recovery requests do not match the durable freezer state",
            )
            .for_operation("recover-qualification-hvf"));
        }
        let prior = self.recovery_calls.fetch_add(1, Ordering::SeqCst);
        if prior != 0 {
            return Err(Error::new(
                ErrorCode::Conflict,
                "qualification HVF replacement recovered more than one durable record",
            )
            .for_operation("recover-qualification-hvf"));
        }
        if matches!(
            record.state.status(),
            ContainerState::Created | ContainerState::Running | ContainerState::Stopped
        ) {
            let observed = self
                .dispatch_create(self.recovery_driver_request(record)?)
                .await?;
            if observed.status() != ContainerState::Created {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    format!(
                        "replacement Guest rebuilt {} with PID {:?}; durable state requires created",
                        observed.status(),
                        observed.pid()
                    ),
                )
                .for_operation("recover-qualification-hvf"));
            }
            self.rehydrated_created_record.store(true, Ordering::SeqCst);
            if *record.state.status() == ContainerState::Created {
                return DriverRecovery::recreated_created(observed);
            }
            let running = self
                .dispatch_start(self.recovery_start_request(record)?)
                .await?;
            if running.status() != ContainerState::Running || running.paused() {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    format!(
                        "replacement Guest rebuilt {} with PID {:?}; durable state requires running",
                        running.status(),
                        running.pid()
                    ),
                )
                .for_operation("recover-qualification-hvf"));
            }
            let running_pid = running.pid().filter(|pid| *pid > 0).ok_or_else(|| {
                Error::new(
                    ErrorCode::Conflict,
                    "replacement Guest rebuilt running state without a positive PID",
                )
                .for_operation("recover-qualification-hvf")
            })?;
            self.rehydrated_running_pid
                .store(running_pid, Ordering::SeqCst);
            self.rehydrated_running_record.store(true, Ordering::SeqCst);
            if *record.state.status() == ContainerState::Running {
                if self.recovery_file.is_some() {
                    let (marker, expected) =
                        self.recovery_file_ready_marker.as_ref().ok_or_else(|| {
                            Error::new(
                                ErrorCode::FailedPrecondition,
                                "qualification HVF File recovery has no init readiness marker",
                            )
                            .for_operation("recover-qualification-hvf")
                        })?;
                    exec::support::wait_for_exact_marker(
                        marker,
                        expected,
                        "replacement File init readiness",
                    )
                    .await
                    .map_err(|reason| {
                        Error::new(ErrorCode::FailedPrecondition, reason)
                            .for_operation("recover-qualification-hvf")
                    })?;
                    let request = self.recovery_file_request(record)?;
                    let expected_target = request.target.clone();
                    let response = self.dispatch_file(request).await?;
                    if response.target != expected_target
                        || response.data.is_some()
                        || response.size == 0
                    {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "replacement Guest rebuilt File with an invalid upload response",
                        )
                        .for_operation("recover-qualification-hvf"));
                    }
                    self.rehydrated_file.store(true, Ordering::SeqCst);
                    return DriverRecovery::recreated_running(running);
                }
                if self.recovery_update.is_some() {
                    let (marker, expected) =
                        self.recovery_update_ready_marker.as_ref().ok_or_else(|| {
                            Error::new(
                                ErrorCode::FailedPrecondition,
                                "qualification HVF Update recovery has no init readiness marker",
                            )
                            .for_operation("recover-qualification-hvf")
                        })?;
                    exec::support::wait_for_exact_marker(
                        marker,
                        expected,
                        "replacement Update init readiness",
                    )
                    .await
                    .map_err(|reason| {
                        Error::new(ErrorCode::FailedPrecondition, reason)
                            .for_operation("recover-qualification-hvf")
                    })?;
                    let updated = self
                        .dispatch_update(self.recovery_update_request(record)?)
                        .await?;
                    if updated.status() != ContainerState::Running
                        || updated.paused()
                        || updated.pid() != Some(running_pid)
                    {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            format!(
                                "replacement Guest rebuilt Update as {} with PID {:?} and paused={}; durable state requires unpaused running PID {running_pid}",
                                updated.status(),
                                updated.pid(),
                                updated.paused()
                            ),
                        )
                        .for_operation("recover-qualification-hvf"));
                    }
                    self.rehydrated_update.store(true, Ordering::SeqCst);
                    return DriverRecovery::recreated_running(updated);
                }
                if self.recovery_pause.is_some() {
                    let (marker, expected) =
                        self.recovery_pause_ready_marker.as_ref().ok_or_else(|| {
                            Error::new(
                                ErrorCode::FailedPrecondition,
                                "qualification HVF Pause recovery has no init readiness marker",
                            )
                            .for_operation("recover-qualification-hvf")
                        })?;
                    exec::support::wait_for_exact_marker(
                        marker,
                        expected,
                        "replacement Pause init readiness",
                    )
                    .await
                    .map_err(|reason| {
                        Error::new(ErrorCode::FailedPrecondition, reason)
                            .for_operation("recover-qualification-hvf")
                    })?;
                    let paused = self
                        .dispatch_pause(self.recovery_pause_request(record)?)
                        .await?;
                    if paused.status() != ContainerState::Running
                        || !paused.paused()
                        || paused.pid() != Some(running_pid)
                    {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            format!(
                                "replacement Guest rebuilt Pause as {} with PID {:?} and paused={}; durable state requires paused running PID {running_pid}",
                                paused.status(),
                                paused.pid(),
                                paused.paused()
                            ),
                        )
                        .for_operation("recover-qualification-hvf"));
                    }
                    self.rehydrated_paused_record.store(true, Ordering::SeqCst);
                    if self.recovery_resume.is_some() {
                        let resumed = self
                            .dispatch_resume(self.recovery_resume_request(record)?)
                            .await?;
                        if resumed.status() != ContainerState::Running
                            || resumed.paused()
                            || resumed.pid() != Some(running_pid)
                        {
                            return Err(Error::new(
                                ErrorCode::Conflict,
                                format!(
                                    "replacement Guest rebuilt Resume as {} with PID {:?} and paused={}; durable state requires unpaused running PID {running_pid}",
                                    resumed.status(),
                                    resumed.pid(),
                                    resumed.paused()
                                ),
                            )
                            .for_operation("recover-qualification-hvf"));
                        }
                        self.rehydrated_resumed_record.store(true, Ordering::SeqCst);
                        return DriverRecovery::recreated_running(resumed);
                    }
                    return DriverRecovery::recreated_paused_running(paused);
                }
                if self.recovery_exec.is_some() {
                    let request = self.recovery_exec_request(record)?;
                    let target = request.target.clone();
                    let process = self.dispatch_exec(request).await?;
                    let pid = process.pid();
                    let durable_pid = u32::try_from(pid).map_err(|error| {
                        Error::new(
                            ErrorCode::Conflict,
                            format!("replacement Guest returned invalid Exec PID {pid}: {error}"),
                        )
                        .for_operation("recover-qualification-hvf")
                    })?;
                    self.rehydrated_exec_pid.store(pid, Ordering::SeqCst);
                    self.rehydrated_exec_record.store(true, Ordering::SeqCst);
                    if self.recovery_signal_process.is_some() {
                        let (marker, expected) =
                            self.recovery_signal_ready_marker.as_ref().ok_or_else(|| {
                                Error::new(
                                    ErrorCode::FailedPrecondition,
                                    "qualification HVF SignalProcess recovery has no Exec readiness marker",
                                )
                                .for_operation("recover-qualification-hvf")
                            })?;
                        exec::support::wait_for_exact_marker(
                            marker,
                            expected,
                            "replacement signalable Exec readiness",
                        )
                        .await
                        .map_err(|reason| {
                            Error::new(ErrorCode::FailedPrecondition, reason)
                                .for_operation("recover-qualification-hvf")
                        })?;
                        let request = self.recovery_signal_process_request(record)?;
                        self.dispatch_signal_process(request).await?;
                        self.rehydrated_signal_process.store(true, Ordering::SeqCst);
                    }
                    if self.recovery_write_stdin.is_some() {
                        let (marker, expected) =
                            self.recovery_write_ready_marker.as_ref().ok_or_else(|| {
                                Error::new(
                                    ErrorCode::FailedPrecondition,
                                    "qualification HVF WriteStdin recovery has no Exec readiness marker",
                                )
                                .for_operation("recover-qualification-hvf")
                            })?;
                        exec::support::wait_for_exact_marker(
                            marker,
                            expected,
                            "replacement stdin Exec readiness",
                        )
                        .await
                        .map_err(|reason| {
                            Error::new(ErrorCode::FailedPrecondition, reason)
                                .for_operation("recover-qualification-hvf")
                        })?;
                        let request = self.recovery_write_stdin_request(record)?;
                        self.dispatch_write_stdin(request).await?;
                        self.rehydrated_write_stdin.store(true, Ordering::SeqCst);
                    }
                    if self.recovery_close_stdin.is_some() {
                        let (marker, expected) =
                            self.recovery_close_ready_marker.as_ref().ok_or_else(|| {
                                Error::new(
                                    ErrorCode::FailedPrecondition,
                                    "qualification HVF CloseStdin recovery has no Exec readiness marker",
                                )
                                .for_operation("recover-qualification-hvf")
                            })?;
                        exec::support::wait_for_exact_marker(
                            marker,
                            expected,
                            "replacement closable stdin Exec readiness",
                        )
                        .await
                        .map_err(|reason| {
                            Error::new(ErrorCode::FailedPrecondition, reason)
                                .for_operation("recover-qualification-hvf")
                        })?;
                        let request = self.recovery_close_stdin_request(record)?;
                        self.dispatch_close_stdin(request).await?;
                        self.rehydrated_close_stdin.store(true, Ordering::SeqCst);
                    }
                    if self.recovery_resize.is_some() {
                        let (marker, expected) =
                            self.recovery_resize_ready_marker.as_ref().ok_or_else(|| {
                                Error::new(
                                    ErrorCode::FailedPrecondition,
                                    "qualification HVF Resize recovery has no Exec readiness marker",
                                )
                                .for_operation("recover-qualification-hvf")
                            })?;
                        exec::support::wait_for_exact_marker(
                            marker,
                            expected,
                            "replacement resizable terminal Exec readiness",
                        )
                        .await
                        .map_err(|reason| {
                            Error::new(ErrorCode::FailedPrecondition, reason)
                                .for_operation("recover-qualification-hvf")
                        })?;
                        let request = self.recovery_resize_request(record)?;
                        self.dispatch_resize(request).await?;
                        self.rehydrated_resize.store(true, Ordering::SeqCst);
                    }
                    if self.recovery_exec_is_live {
                        return DriverRecovery::recreated_running_with_processes(
                            running,
                            vec![ProcessRecord {
                                target,
                                pid: Some(durable_pid),
                                terminal: process.terminal(),
                            }],
                        );
                    }
                    return DriverRecovery::recreated_running(running);
                }
                return DriverRecovery::recreated_running(running);
            }
            let marker = self.recovery_marker.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorCode::FailedPrecondition,
                    "qualification HVF stopped recovery has no workload marker",
                )
                .for_operation("recover-qualification-hvf")
            })?;
            wait_for_replacement_marker(marker)
                .await
                .map_err(|reason| {
                    Error::new(ErrorCode::FailedPrecondition, reason)
                        .for_operation("recover-qualification-hvf")
                })?;
            let stopped = self
                .dispatch_kill(self.recovery_kill_request(record)?)
                .await?;
            if stopped.status() != ContainerState::Stopped || stopped.pid().is_some() {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    format!(
                        "replacement Guest rebuilt {} with PID {:?}; durable state requires stopped",
                        stopped.status(),
                        stopped.pid()
                    ),
                )
                .for_operation("recover-qualification-hvf"));
            }
            self.rehydrated_stopped_record.store(true, Ordering::SeqCst);
            return Ok(DriverRecovery::observed(stopped));
        }
        Ok(DriverRecovery::none())
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.dispatch_create(request).await
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.client.state(target).await
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.dispatch_start(request).await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        self.dispatch_kill(request).await
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.dispatch_delete(request).await
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.dispatch_wait(request).await
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.dispatch_exec(request).await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.dispatch_signal_process(request).await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.dispatch_write_stdin(request).await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.dispatch_close_stdin(request).await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.dispatch_resize(request).await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.dispatch_file(request).await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.dispatch_pause(request).await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.dispatch_resume(request).await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.dispatch_processes(target).await
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.dispatch_update(request).await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.dispatch_stats(target).await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.dispatch_read_output(request).await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.dispatch_wait_process(request).await
    }
}

async fn wait_for_replacement_marker(marker: &Path) -> std::result::Result<(), String> {
    let deadline = Instant::now() + QUALIFICATION_TIMEOUT;
    loop {
        if path_exists(marker).await? {
            let contents = read_marker(marker).await?;
            match exact_marker_state(&contents, REPLACEMENT_MARKER_CONTENTS) {
                ExactMarkerState::Complete => return Ok(()),
                ExactMarkerState::InProgress => {}
                ExactMarkerState::Mismatch => {
                    return Err(
                        "replacement workload produced unexpected marker contents".to_string()
                    );
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "replacement workload did not produce its marker within {} seconds",
                QUALIFICATION_TIMEOUT.as_secs()
            ));
        }
        sleep(MARKER_POLL_INTERVAL).await;
    }
}

async fn create_qualification_state_root(path: &Path) -> std::result::Result<(), String> {
    if path_exists(path).await? {
        return Err(format!(
            "refusing to reuse qualification state root: {}",
            path.display()
        ));
    }
    tokio::fs::create_dir(path).await.map_err(|error| {
        format!(
            "failed to create qualification state root {}: {error}",
            path.display()
        )
    })?;
    use std::os::unix::fs::PermissionsExt;
    if let Err(error) =
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await
    {
        let cleanup = tokio::fs::remove_dir(path).await.err();
        return Err(format!(
            "failed to protect qualification state root {}: {error}{}",
            path.display(),
            cleanup.map_or_else(String::new, |cleanup| format!(
                "; failed to remove the unprotected directory: {cleanup}"
            ))
        ));
    }
    Ok(())
}

fn owner_identities_are_distinct(
    first: &AgentVmSmokeReport,
    replacement: &AgentVmSmokeReport,
) -> bool {
    first
        .endpoint_name
        .as_deref()
        .zip(replacement.endpoint_name.as_deref())
        .is_some_and(|(first, replacement)| !first.is_empty() && first != replacement)
        && first
            .shim_process_id
            .zip(replacement.shim_process_id)
            .is_some_and(|(first, replacement)| first != 0 && first != replacement)
        && first
            .bridge_process_id
            .zip(replacement.bridge_process_id)
            .is_some_and(|(first, replacement)| first != 0 && first != replacement)
}

fn record_first_interruption(
    report: &mut OciVmReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    report.first_create_error_code = Some(error.code);
    report.first_create_error_operation = error.operation.clone();
    report.first_create_error_retryable = error.retryable;
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
            "first owner returned an unexpected transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

fn append_failure(target: &mut Option<String>, reason: impl Into<String>) {
    let reason = reason.into();
    *target = Some(match target.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn append_reason(report: &mut OciVmReopenReplacementReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmReopenReplacementReport,
    reason: impl Into<String>,
) -> OciVmReopenReplacementReport {
    append_reason(&mut report, reason);
    report
}
