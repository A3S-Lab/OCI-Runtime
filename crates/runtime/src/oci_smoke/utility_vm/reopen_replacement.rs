use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    async_trait, ContainerRecord, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode,
    DeleteRequest, Error, ErrorCode, IoMode, IsolationRequest, ListRequest, OciBundle,
    OciRuntimeService, OperationContext, OperationId, ProcessIo, Result, StartRequest,
    StateRequest,
};
use tokio::time::timeout;

use super::transport_fault_cleanup::{read_guest_qualification_evidence, HostTransportFault};
use super::{
    canonical_directory, fixed_rootfs, guest_path, path_exists, remove_marker, runtime_entries,
    target, unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use crate::agent_driver::AgentDriverClient;
use crate::agent_session::UtilityVmSession;
use crate::driver::{
    DriverCreateAttachments, DriverCreateRequest, DriverDeleteRequest, DriverKillRequest,
    DriverStartRequest, DriverState, RuntimeDriver,
};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{AgentVmSmokeReport, DriverRecovery, OciVmReopenReplacementReport};

const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(15);
const FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";

mod state;
pub(super) use state::run as run_state;
mod start;
pub(super) use start::run as run_start;

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
    recovery_calls: AtomicU32,
    rehydrated_created_record: AtomicBool,
    rehydrated_running_record: AtomicBool,
    create_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    start_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    start_calls: AtomicU32,
}

impl QualificationHvfDriver {
    fn new(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
    ) -> Self {
        Self::with_optional_start(session, vm_rootfs, recovery_create, None)
    }

    fn with_start_recovery(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: StartRequest,
    ) -> Self {
        Self::with_optional_start(session, vm_rootfs, recovery_create, Some(recovery_start))
    }

    fn with_optional_start(
        session: Arc<UtilityVmSession>,
        vm_rootfs: PathBuf,
        recovery_create: CreateRequest,
        recovery_start: Option<StartRequest>,
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
            recovery_calls: AtomicU32::new(0),
            rehydrated_created_record: AtomicBool::new(false),
            rehydrated_running_record: AtomicBool::new(false),
            create_identity: StdMutex::new(None),
            start_identity: StdMutex::new(None),
            start_calls: AtomicU32::new(0),
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

    fn start_calls(&self) -> u32 {
        self.start_calls.load(Ordering::SeqCst)
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

    async fn recover(&self, record: &ContainerRecord) -> Result<DriverRecovery> {
        let recovery_state_supported = matches!(
            record.state.status(),
            ContainerState::Creating | ContainerState::Created
        ) || (*record.state.status() == ContainerState::Running
            && self.recovery_start.is_some());
        if record.driver != DriverKind::LibkrunHvf
            || record.isolation != IsolationClass::DedicatedVm
            || !recovery_state_supported
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement accepts only its interrupted Create or Start record",
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
            ContainerState::Created | ContainerState::Running
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
            self.rehydrated_running_record.store(true, Ordering::SeqCst);
            return DriverRecovery::recreated_running(running);
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
        self.client.kill(request).await
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.client.delete(request).await
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
