use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentTransportFaultInjector, AgentTransportFaultStage, AgentTransportOperationStage,
    GuestAgentService,
};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, HostPlatform, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerRecord, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode,
    DeleteRequest, Error, ErrorCode, IoMode, IsolationRequest, ListRequest, OciBundle,
    OciRuntimeService, OperationContext, OperationId, ProcessIo, Result,
};
use tokio::time::timeout;

use super::transport_fault_cleanup::HostTransportFault;
use super::{
    canonical_directory, fixed_rootfs, guest_path, path_exists, remove_marker, runtime_entries,
    target, unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use crate::agent_driver::AgentDriverClient;
use crate::agent_session::UtilityVmSession;
use crate::driver::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, DriverState,
    RuntimeDriver,
};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::{AgentVmSmokeReport, DriverRecovery, OciVmReopenReplacementReport};

const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(15);
const FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
) -> OciVmReopenReplacementReport {
    let mut report = OciVmReopenReplacementReport::initial(HostPlatform::current());
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
    report: &mut OciVmReopenReplacementReport,
) -> std::result::Result<(), String> {
    let stage = AgentTransportOperationStage::HostBeforeRequestWrite;
    let faults = Arc::new(HostTransportFault::new(AgentTransportFaultStage::from(
        stage,
    )));
    let first_cleanup = MacosHostCleanupTracker::capture();
    let first_session = match UtilityVmSession::connect_with_host_fault_injector(
        shim,
        vm_rootfs,
        first_console,
        Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>,
    )
    .await
    {
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

    let mut first_failure =
        match timeout(QUALIFICATION_TIMEOUT, first_service.create(request.clone())).await {
            Ok(Err(error)) => {
                report.first_create_error_code = Some(error.code);
                report.first_create_error_operation = error.operation.clone();
                report.first_create_error_retryable = error.retryable;
                if error.code == ErrorCode::Unavailable
                    && error.operation.as_deref() == Some(FAULT_OPERATION)
                    && error.retryable
                {
                    None
                } else {
                    Some(format!(
                        "first create returned an unexpected transport error: {error}"
                    ))
                }
            }
            Ok(Ok(_)) => {
                Some("first create unexpectedly completed before owner replacement".into())
            }
            Err(_) => Some(format!(
                "first create exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            )),
        };
    report.negotiated_protocol = faults.protocol_version();
    report.injected_point = faults.injected_point();
    report.fault_crossings = faults.crossing_count();

    match first_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_before_reopen = Some(record.generation);
            report.durable_creating_retained = *record.state.status() == ContainerState::Creating
                && record.state.id() == request.id.as_str()
                && record.driver == DriverKind::LibkrunHvf
                && record.isolation == IsolationClass::DedicatedVm;
            if !report.durable_creating_retained {
                append_failure(
                    &mut first_failure,
                    "interrupted create did not retain the exact durable creating record",
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
            service
        }
        Err(error) => {
            report.replacement_recovery_calls = replacement_driver.recovery_calls();
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
    recovery_calls: AtomicU32,
    create_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
}

impl QualificationHvfDriver {
    fn new(session: Arc<UtilityVmSession>, vm_rootfs: PathBuf) -> Self {
        let service: Arc<dyn GuestAgentService> = Arc::new(session.client());
        Self {
            client: AgentDriverClient::new(
                service,
                "qualification-only HVF guest agent",
                "qualification-hvf",
            ),
            session,
            vm_rootfs,
            recovery_calls: AtomicU32::new(0),
            create_identity: StdMutex::new(None),
        }
    }

    fn recovery_calls(&self) -> u32 {
        self.recovery_calls.load(Ordering::SeqCst)
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

    fn guest_bundle(&self, bundle: &OciBundle) -> Result<a3s_oci_agent_protocol::GuestPath> {
        guest_path(&self.vm_rootfs, bundle.directory()).map_err(|reason| {
            Error::new(ErrorCode::FailedPrecondition, reason)
                .for_operation("map-qualification-hvf-bundle")
        })
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
        if record.driver != DriverKind::LibkrunHvf
            || record.isolation != IsolationClass::DedicatedVm
            || *record.state.status() != ContainerState::Creating
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "qualification HVF replacement accepts only its interrupted creating record",
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
        Ok(DriverRecovery::none())
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
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

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.client.state(target).await
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.client.start(request).await
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
