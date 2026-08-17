use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{DriverKind, RuntimeFeatures};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, CheckpointRequest, CloseStdinRequest, ContainerId,
    ContainerOperationRequest, ContainerRecord, ContainerStats, ContainerTarget, CreateRequest,
    DeleteRequest, Error, ErrorCode, EventBatch, EventsRequest, ExecRequest, ExitStatus, FileOp,
    FileRequest, FileResponse, FilesystemOp, FilesystemRequest, FilesystemResponse, KillRequest,
    ListRequest, OciRuntimeService, OutputChunk, ProcessId, ProcessRecord, ProcessTarget,
    ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest, Result, RuntimeInfo,
    RuntimeOperation, SignalProcessRequest, StartRequest, StateRequest, StatsRequest,
    UpdateRequest, ValidateRequest, WaitProcessRequest, WaitRequest, WriteStdinRequest,
    MAX_FILE_TRANSFER_BYTES,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateAttachments,
    DriverCreateRequest, DriverDeleteRequest, DriverExecRequest, DriverKillRequest,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest, DriverWriteStdinRequest,
    RecreatedProcess, RuntimeDriver,
};
use crate::fault::{
    DriverBoundaryStage, DriverOperation, FaultInjector, FaultPoint, NoFaultInjector,
};
use crate::state::{
    DeletePreparation, DurableStateStore, FilesystemMutationPreparation, ProcessIoPreparation,
    ProcessOperationPreparation, ProcessWaitPreparation, RecordOperationPreparation,
    SignalProcessPreparation,
};

mod driver_registry;
mod feature_report;

use driver_registry::{DriverRegistration, DriverRegistry, RegisteredDriver};

/// In-process host implementation used by the CLI and A3S Box adapter.
#[derive(Clone, Default)]
pub struct HostRuntimeService {
    lifecycle: Option<Arc<LifecycleHost>>,
    #[cfg(target_os = "linux")]
    native_control: Option<Arc<BoundNativeControl>>,
}

#[cfg(target_os = "linux")]
struct BoundNativeControl {
    container_id: ContainerId,
    descriptors: crate::NativeControlDescriptors,
}

struct LifecycleHost {
    store: DurableStateStore,
    drivers: DriverRegistry,
    faults: Arc<dyn FaultInjector>,
}

impl fmt::Debug for HostRuntimeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRuntimeService")
            .field(
                "drivers",
                &self
                    .lifecycle
                    .as_ref()
                    .map(|lifecycle| lifecycle.drivers.kinds()),
            )
            .finish()
    }
}

impl HostRuntimeService {
    /// Construct the probe-only local host service.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lifecycle: None,
            #[cfg(target_os = "linux")]
            native_control: None,
        }
    }

    /// Open durable lifecycle orchestration around one fully enforcing driver.
    pub async fn open(
        state_root: impl AsRef<Path>,
        driver: Arc<dyn RuntimeDriver>,
    ) -> Result<Self> {
        Self::open_with_fault_injector(state_root, driver, Arc::new(NoFaultInjector)).await
    }

    /// Open durable lifecycle orchestration around a deterministic driver set.
    ///
    /// Every isolation class must have exactly one owner. Drivers in one host
    /// service must expose the same operation and hook surface so feature
    /// discovery cannot overstate support for a selected workload.
    pub async fn open_with_drivers(
        state_root: impl AsRef<Path>,
        drivers: Vec<Arc<dyn RuntimeDriver>>,
    ) -> Result<Self> {
        Self::open_with_drivers_and_fault_injector(state_root, drivers, Arc::new(NoFaultInjector))
            .await
    }

    /// Open one native Linux service whose normal SDK `create` operation
    /// carries the A3S Box control descriptors for exactly one container ID.
    ///
    /// This binding lets an out-of-process runtime owner expose only the
    /// transport-neutral [`OciRuntimeService`] API while retaining the
    /// process-local listener and log handles inherited at service startup.
    #[cfg(target_os = "linux")]
    pub async fn open_with_native_control_descriptors(
        state_root: impl AsRef<Path>,
        driver: Arc<dyn RuntimeDriver>,
        container_id: ContainerId,
        descriptors: crate::NativeControlDescriptors,
    ) -> Result<Self> {
        descriptors.descriptor_plan()?;
        let mut service = Self::open(state_root, driver).await?;
        service.native_control = Some(Arc::new(BoundNativeControl {
            container_id,
            descriptors,
        }));
        Ok(service)
    }

    pub(crate) async fn open_with_fault_injector(
        state_root: impl AsRef<Path>,
        driver: Arc<dyn RuntimeDriver>,
        faults: Arc<dyn FaultInjector>,
    ) -> Result<Self> {
        Self::open_with_drivers_and_fault_injector(state_root, vec![driver], faults).await
    }

    async fn open_with_drivers_and_fault_injector(
        state_root: impl AsRef<Path>,
        drivers: Vec<Arc<dyn RuntimeDriver>>,
        faults: Arc<dyn FaultInjector>,
    ) -> Result<Self> {
        let mut registrations = Vec::with_capacity(drivers.len());
        for driver in drivers {
            faults.check(FaultPoint::DriverBoundary {
                operation: DriverOperation::Capability,
                stage: DriverBoundaryStage::BeforeCall,
            })?;
            let capability = driver.capability();
            faults.check(FaultPoint::DriverBoundary {
                operation: DriverOperation::Capability,
                stage: DriverBoundaryStage::AfterCall,
            })?;
            registrations.push(DriverRegistration { driver, capability });
        }
        let drivers = DriverRegistry::new(registrations)?;
        let store =
            DurableStateStore::open_with_fault_injector(state_root, Arc::clone(&faults)).await?;
        for record in store.list(&ListRequest::default()).await? {
            let registered = drivers.validate_durable_record(&record)?;
            faults.check(FaultPoint::DriverBoundary {
                operation: DriverOperation::Recover,
                stage: DriverBoundaryStage::BeforeCall,
            })?;
            let recovery = registered.driver().recover(&record).await?;
            faults.check(FaultPoint::DriverBoundary {
                operation: DriverOperation::Recover,
                stage: DriverBoundaryStage::AfterCall,
            })?;
            let recreated_process = recovery.recreated_process();
            let recreated_exec_processes = recovery.recreated_exec_processes().to_vec();
            let target =
                ContainerTarget::exact(ContainerId::new(record.state.id())?, record.generation);
            let (observation, init_exit_status) = recovery.into_parts();
            if let Some(observation) = observation {
                match recreated_process {
                    RecreatedProcess::Created => {
                        store
                            .observe_recreated_created_process(&target, observation)
                            .await?;
                    }
                    RecreatedProcess::Running => {
                        store
                            .observe_recreated_running_process(&target, observation)
                            .await?;
                        store
                            .observe_recreated_exec_processes(&target, &recreated_exec_processes)
                            .await?;
                    }
                    RecreatedProcess::RunningPaused => {
                        store
                            .observe_recreated_paused_running_process(&target, observation)
                            .await?;
                    }
                    RecreatedProcess::None => {
                        store
                            .observe_state_with_pause(
                                &target,
                                observation.status(),
                                observation.pid(),
                                observation.paused(),
                            )
                            .await?;
                    }
                }
            }
            if let Some(status) = init_exit_status {
                store
                    .complete_process_wait(
                        &ProcessTarget {
                            container: target,
                            process_id: ProcessId::init(),
                        },
                        status,
                    )
                    .await?;
            }
        }
        Ok(Self {
            lifecycle: Some(Arc::new(LifecycleHost {
                store,
                drivers,
                faults,
            })),
            #[cfg(target_os = "linux")]
            native_control: None,
        })
    }

    fn lifecycle(&self, operation: &'static str) -> Result<&LifecycleHost> {
        self.lifecycle
            .as_deref()
            .ok_or_else(|| Error::unsupported(operation))
    }

    fn runtime_features(&self) -> RuntimeFeatures {
        let mut features = crate::features();
        if let Some(lifecycle) = &self.lifecycle {
            for capability in lifecycle.drivers.capabilities() {
                if let Some(existing) = features
                    .drivers
                    .iter_mut()
                    .find(|entry| entry.driver == capability.driver)
                {
                    *existing = capability.clone();
                } else {
                    features.drivers.push(capability.clone());
                }
            }
            features.drivers.sort_by_key(|entry| entry.driver);
        }
        features
    }

    /// Create a native Linux container with the A3S Box control listeners and
    /// dedicated init log inherited as descriptors 3, 4, and 5.
    #[cfg(target_os = "linux")]
    pub async fn create_with_native_control_descriptors(
        &self,
        request: CreateRequest,
        descriptors: crate::NativeControlDescriptors,
    ) -> Result<ContainerRecord> {
        // Revalidate immediately before durable reservation. The private
        // handles cannot be replaced through safe code, but this also fails
        // closed if external unsafe code closed a process-wide descriptor.
        descriptors.descriptor_plan()?;
        self.create_internal(request, DriverCreateAttachments::NativeControl(descriptors))
            .await
    }

    async fn create_internal(
        &self,
        request: CreateRequest,
        attachments: DriverCreateAttachments,
    ) -> Result<ContainerRecord> {
        request.validate()?;
        let lifecycle = self.lifecycle("create")?;
        let registered = lifecycle
            .drivers
            .select(request.isolation.class(), "create")?;
        registered
            .attachment_capabilities()
            .require(&request.attachments)?;
        lifecycle.ensure_attachments(registered, &attachments)?;
        let attachment_schema = attachments.schema();
        let prepared = lifecycle
            .store
            .prepare_create_with_inherited_descriptors(
                &request,
                registered.kind(),
                attachment_schema.as_ref(),
            )
            .await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(record))
                    .await;
            }
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.id.clone(), record.generation);
        let durable_bundle = lifecycle.store.bundle(&target).await?;
        let mut driver_request = DriverCreateRequest {
            context: request.context.clone(),
            target,
            bundle: durable_bundle,
            isolation: request.isolation,
            io: request.attachments.process_io().clone(),
            attachment_contract: request.attachments,
            attachments,
        };
        lifecycle.driver_boundary(DriverOperation::Create, DriverBoundaryStage::BeforeCall)?;
        let staged_bundle = match registered
            .driver()
            .prepare_create_bundle(&driver_request)
            .await
        {
            Ok(bundle) => bundle,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        if staged_bundle.config_bytes() != driver_request.bundle.config_bytes()
            || staged_bundle.config_digest() != driver_request.bundle.config_digest()
        {
            let error = Error::new(
                ErrorCode::FailedPrecondition,
                "driver create-bundle preparation changed immutable configuration bytes",
            )
            .for_operation("create");
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        if let Err(error) = driver_request.attachment_contract.validate(&staged_bundle) {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        driver_request.bundle = staged_bundle;
        let result = registered.driver().create(driver_request).await;
        lifecycle.driver_boundary(DriverOperation::Create, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        if observed.status() != ContainerState::Created {
            let error = driver_state_error("create", ContainerState::Created, observed.status());
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let pid = observed.pid().ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "created driver state did not contain an init PID",
            )
            .for_operation("create")
        })?;
        let completed = lifecycle
            .store
            .complete_create(&request.context.operation_id, pid)
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }
}

impl LifecycleHost {
    fn driver_boundary(
        &self,
        operation: DriverOperation,
        stage: DriverBoundaryStage,
    ) -> Result<()> {
        self.faults
            .check(FaultPoint::DriverBoundary { operation, stage })
    }

    fn ensure_attachments(
        &self,
        registered: &RegisteredDriver,
        attachments: &DriverCreateAttachments,
    ) -> Result<()> {
        if attachments.is_empty() || registered.kind() == DriverKind::NativeLinux {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "driver {:?} does not accept native inherited descriptors",
                    registered.kind()
                ),
            )
            .for_operation("create"))
        }
    }

    fn driver(&self, kind: DriverKind, operation: &'static str) -> Result<&RegisteredDriver> {
        self.drivers.get(kind, operation)
    }

    fn ensure_operation(&self, operation: RuntimeOperation, name: &'static str) -> Result<()> {
        if self.drivers.operations().contains(&operation) {
            Ok(())
        } else {
            Err(Error::unsupported(name))
        }
    }

    async fn fail_driver_operation<T>(
        &self,
        operation_id: &a3s_oci_sdk::OperationId,
        error: Error,
    ) -> Result<T> {
        if error.retryable {
            return Err(error);
        }
        self.store.fail_operation(operation_id, &error).await?;
        self.drivers.acknowledge_operation(operation_id).await?;
        Err(error)
    }

    async fn acknowledge_operation(&self, operation_id: &a3s_oci_sdk::OperationId) -> Result<()> {
        self.drivers.acknowledge_operation(operation_id).await
    }

    async fn acknowledge_result<T>(
        &self,
        operation_id: &a3s_oci_sdk::OperationId,
        result: Result<T>,
    ) -> Result<T> {
        let value = result?;
        self.acknowledge_operation(operation_id).await?;
        Ok(value)
    }

    async fn complete_process_wait(
        &self,
        target: &ProcessTarget,
        status: ExitStatus,
    ) -> Result<ExitStatus> {
        if target.process_id.is_init() {
            self.store
                .observe_state(&target.container, ContainerState::Stopped, None)
                .await?;
        }
        self.store.complete_process_wait(target, status).await
    }
}

fn driver_state_error(
    operation: &'static str,
    expected: ContainerState,
    observed: ContainerState,
) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "driver violated the OCI {operation} barrier: expected {expected}, observed {observed}"
        ),
    )
    .for_operation(operation)
}

#[async_trait]
impl OciRuntimeService for HostRuntimeService {
    async fn features(&self) -> Result<RuntimeInfo> {
        let hooks = self
            .lifecycle
            .as_deref()
            .map_or([].as_slice(), |lifecycle| lifecycle.drivers.hooks());
        let attachments = self
            .lifecycle
            .as_deref()
            .map_or_else(AttachmentCapabilities::base_v1, |lifecycle| {
                lifecycle.drivers.attachment_capabilities().clone()
            });
        let oci = feature_report::build(self.lifecycle.is_some(), hooks, &attachments)?;

        let mut operations = BTreeSet::from([RuntimeOperation::Features]);
        if let Some(lifecycle) = &self.lifecycle {
            operations.insert(RuntimeOperation::Events);
            operations.insert(RuntimeOperation::List);
            operations.extend(lifecycle.drivers.operations().iter().copied());
        }
        Ok(RuntimeInfo {
            oci,
            drivers: self.runtime_features(),
            operations: operations.into_iter().collect(),
            attachments,
        })
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        #[cfg(target_os = "linux")]
        let attachments = match &self.native_control {
            Some(binding) if request.id == binding.container_id => {
                DriverCreateAttachments::NativeControl(binding.descriptors.clone())
            }
            Some(binding) => {
                return Err(Error::new(
                    ErrorCode::PermissionDenied,
                    format!(
                        "native control service is bound to container {}; refusing create for {}",
                        binding.container_id, request.id
                    ),
                )
                .for_operation("create"));
            }
            None => DriverCreateAttachments::None,
        };
        #[cfg(not(target_os = "linux"))]
        let attachments = DriverCreateAttachments::None;

        self.create_internal(request, attachments).await
    }

    async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("state")?;
        request.validate()?;
        let durable = lifecycle.store.state(&request.target).await?;
        if *durable.state.status() == ContainerState::Creating {
            return Ok(durable);
        }
        let registered = lifecycle.driver(durable.driver, "state")?;
        let target = ContainerTarget::exact(request.target.id, durable.generation);
        lifecycle.driver_boundary(DriverOperation::State, DriverBoundaryStage::BeforeCall)?;
        let result = registered.driver().state(target.clone()).await;
        lifecycle.driver_boundary(DriverOperation::State, DriverBoundaryStage::AfterCall)?;
        let observed = result?;
        lifecycle
            .store
            .observe_state_with_pause(
                &target,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await
    }

    async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("start")?;
        let prepared = lifecycle.store.prepare_start(&request).await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(record))
                    .await;
            }
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let registered = lifecycle.driver(record.driver, "start")?;
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        let bundle = lifecycle.store.bundle(&target).await?;
        lifecycle.driver_boundary(DriverOperation::Start, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .start(DriverStartRequest {
                context: request.context.clone(),
                target,
                bundle,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Start, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        if !matches!(
            observed.status(),
            ContainerState::Running | ContainerState::Stopped
        ) {
            let error = driver_state_error("start", ContainerState::Running, observed.status());
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let completed = lifecycle
            .store
            .complete_start(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
            )
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("kill")?;
        let prepared = lifecycle.store.prepare_kill(&request).await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(record))
                    .await;
            }
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let registered = lifecycle.driver(record.driver, "kill")?;
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Kill, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .kill(DriverKillRequest {
                context: request.context.clone(),
                target,
                signal: request.signal,
                all: request.all,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Kill, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        let completed = lifecycle
            .store
            .complete_kill(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
            )
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn delete(&self, request: DeleteRequest) -> Result<()> {
        let lifecycle = self.lifecycle("delete")?;
        let prepared = lifecycle.store.prepare_delete(&request).await?;
        let record = match prepared {
            DeletePreparation::Replayed => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(()))
                    .await;
            }
            DeletePreparation::Prepared(record) | DeletePreparation::Resume(record) => record,
        };
        let registered = lifecycle.driver(record.driver, "delete")?;
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Delete, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .delete(DriverDeleteRequest {
                context: request.context.clone(),
                target,
                mode: request.mode,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Delete, DriverBoundaryStage::AfterCall)?;
        if let Err(error) = result {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let completed = lifecycle
            .store
            .complete_delete(&request.context.operation_id)
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn exec(&self, request: ExecRequest) -> Result<ProcessRecord> {
        let lifecycle = self.lifecycle("exec")?;
        lifecycle.ensure_operation(RuntimeOperation::Exec, "exec")?;
        let prepared = lifecycle.store.prepare_exec(&request).await?;
        let durable = match prepared {
            ProcessOperationPreparation::Replayed(record) => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(record))
                    .await;
            }
            ProcessOperationPreparation::Prepared(record)
            | ProcessOperationPreparation::Resume(record) => record,
        };
        let target = durable.target;
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "exec")?;
        registered.ensure_operation(RuntimeOperation::Exec, "exec")?;
        lifecycle.driver_boundary(DriverOperation::Exec, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .exec(DriverExecRequest {
                context: request.context.clone(),
                target,
                process: request.process,
                io: request.io,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Exec, DriverBoundaryStage::AfterCall)?;
        let process = match result {
            Ok(process) => process,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        let completed = lifecycle
            .store
            .complete_exec(
                &request.context.operation_id,
                process.pid(),
                process.terminal(),
            )
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn wait(&self, request: WaitRequest) -> Result<ExitStatus> {
        let lifecycle = self.lifecycle("wait")?;
        lifecycle.ensure_operation(RuntimeOperation::Wait, "wait")?;
        request.validate()?;
        let process_request = WaitProcessRequest {
            process: ProcessTarget {
                container: request.target,
                process_id: ProcessId::init(),
            },
            timeout_ms: request.timeout_ms,
        };
        let target = match lifecycle
            .store
            .prepare_wait_process(&process_request)
            .await?
        {
            ProcessWaitPreparation::Replayed(status) => return Ok(status),
            ProcessWaitPreparation::Prepared(target) => target,
        };
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "wait")?;
        registered.ensure_operation(RuntimeOperation::Wait, "wait")?;
        lifecycle.driver_boundary(DriverOperation::Wait, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .wait(DriverWaitRequest {
                target: target.container.clone(),
                timeout_ms: request.timeout_ms,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Wait, DriverBoundaryStage::AfterCall)?;
        let status = result?;
        status.validate()?;
        lifecycle.complete_process_wait(&target, status).await
    }

    async fn list(&self, request: ListRequest) -> Result<Vec<ContainerRecord>> {
        self.lifecycle("list")?.store.list(&request).await
    }

    async fn pause(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("pause")?;
        lifecycle.ensure_operation(RuntimeOperation::Pause, "pause")?;
        let record = match lifecycle.store.prepare_pause(&request).await? {
            RecordOperationPreparation::Replayed(record) => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(record))
                    .await;
            }
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let registered = lifecycle.driver(record.driver, "pause")?;
        registered.ensure_operation(RuntimeOperation::Pause, "pause")?;
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Pause, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .pause(DriverContainerOperationRequest {
                context: request.context.clone(),
                target,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Pause, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        let completed = lifecycle
            .store
            .complete_pause(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn resume(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("resume")?;
        lifecycle.ensure_operation(RuntimeOperation::Resume, "resume")?;
        let record = match lifecycle.store.prepare_resume(&request).await? {
            RecordOperationPreparation::Replayed(record) => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(record))
                    .await;
            }
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let registered = lifecycle.driver(record.driver, "resume")?;
        registered.ensure_operation(RuntimeOperation::Resume, "resume")?;
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Resume, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .resume(DriverContainerOperationRequest {
                context: request.context.clone(),
                target,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Resume, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        let completed = lifecycle
            .store
            .complete_resume(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn update(&self, request: UpdateRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("update")?;
        lifecycle.ensure_operation(RuntimeOperation::Update, "update")?;
        let record = match lifecycle.store.prepare_update(&request).await? {
            RecordOperationPreparation::Replayed(record) => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(record))
                    .await;
            }
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let registered = lifecycle.driver(record.driver, "update")?;
        registered.ensure_operation(RuntimeOperation::Update, "update")?;
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Update, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .update(DriverUpdateRequest {
                context: request.context.clone(),
                target,
                resources: request.resources,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Update, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        let completed = lifecycle
            .store
            .complete_update(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn processes(&self, request: ProcessesRequest) -> Result<Vec<ProcessRecord>> {
        let lifecycle = self.lifecycle("processes")?;
        lifecycle.ensure_operation(RuntimeOperation::Processes, "processes")?;
        request.validate()?;
        let record = lifecycle.store.state(&request.target).await?;
        let registered = lifecycle.driver(record.driver, "processes")?;
        registered.ensure_operation(RuntimeOperation::Processes, "processes")?;
        let target = ContainerTarget::exact(request.target.id, record.generation);
        lifecycle.driver_boundary(DriverOperation::Processes, DriverBoundaryStage::BeforeCall)?;
        let result = registered.driver().processes(target.clone()).await;
        lifecycle.driver_boundary(DriverOperation::Processes, DriverBoundaryStage::AfterCall)?;
        let mut processes = result?;
        for (index, process) in processes.iter().enumerate() {
            if process.target.container != target
                || process.pid.is_none_or(|pid| pid == 0)
                || processes[..index]
                    .iter()
                    .any(|candidate| candidate.target.process_id == process.target.process_id)
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "runtime driver returned an invalid process inventory",
                )
                .for_operation("processes"));
            }
        }
        if *record.state.status() != ContainerState::Stopped
            && !processes
                .iter()
                .any(|process| process.target.process_id.is_init())
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "runtime driver omitted the live init process from its inventory",
            )
            .for_operation("processes"));
        }
        processes.sort_by(|left, right| {
            left.target
                .process_id
                .as_ref()
                .cmp(right.target.process_id.as_ref())
        });
        Ok(processes)
    }

    async fn stats(&self, request: StatsRequest) -> Result<ContainerStats> {
        let lifecycle = self.lifecycle("stats")?;
        lifecycle.ensure_operation(RuntimeOperation::Stats, "stats")?;
        request.validate()?;
        let record = lifecycle.store.state(&request.target).await?;
        let registered = lifecycle.driver(record.driver, "stats")?;
        registered.ensure_operation(RuntimeOperation::Stats, "stats")?;
        let target = ContainerTarget::exact(request.target.id, record.generation);
        lifecycle.driver_boundary(DriverOperation::Stats, DriverBoundaryStage::BeforeCall)?;
        let result = registered.driver().stats(target.clone()).await;
        lifecycle.driver_boundary(DriverOperation::Stats, DriverBoundaryStage::AfterCall)?;
        let stats = result?;
        if stats.target != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "runtime driver returned stats for a different container generation",
            )
            .for_operation("stats"));
        }
        stats.validate()?;
        if *record.state.status() != ContainerState::Stopped && stats.process_count == 0 {
            return Err(Error::new(
                ErrorCode::Conflict,
                "runtime driver returned zero processes for a live container",
            )
            .for_operation("stats"));
        }
        Ok(stats)
    }

    async fn events(&self, request: EventsRequest) -> Result<EventBatch> {
        self.lifecycle("events")?.store.events(&request).await
    }

    async fn read_output(&self, request: ReadOutputRequest) -> Result<Vec<OutputChunk>> {
        let lifecycle = self.lifecycle("read-output")?;
        lifecycle.ensure_operation(RuntimeOperation::ReadOutput, "read-output")?;
        request.validate()?;
        let target = lifecycle
            .store
            .resolve_process_target(&request.process, "read-output")
            .await?;
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "read-output")?;
        registered.ensure_operation(RuntimeOperation::ReadOutput, "read-output")?;
        lifecycle.driver_boundary(DriverOperation::ReadOutput, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .read_output(DriverReadOutputRequest {
                target,
                after_sequence: request.after_sequence,
                max_bytes: request.max_bytes,
                wait_timeout_ms: request.wait_timeout_ms,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::ReadOutput, DriverBoundaryStage::AfterCall)?;
        let chunks = result?;
        validate_output_chunks(&chunks, request.after_sequence, request.max_bytes)?;
        Ok(chunks)
    }

    async fn write_stdin(&self, request: WriteStdinRequest) -> Result<()> {
        let lifecycle = self.lifecycle("write-stdin")?;
        lifecycle.ensure_operation(RuntimeOperation::WriteStdin, "write-stdin")?;
        let target = match lifecycle.store.prepare_write_stdin(&request).await? {
            ProcessIoPreparation::Replayed => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(()))
                    .await;
            }
            ProcessIoPreparation::Prepared(target) | ProcessIoPreparation::Resume(target) => target,
        };
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "write-stdin")?;
        registered.ensure_operation(RuntimeOperation::WriteStdin, "write-stdin")?;
        lifecycle.driver_boundary(DriverOperation::WriteStdin, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .write_stdin(DriverWriteStdinRequest {
                context: request.context.clone(),
                target,
                data: request.data,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::WriteStdin, DriverBoundaryStage::AfterCall)?;
        if let Err(error) = result {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let completed = lifecycle
            .store
            .complete_write_stdin(&request.context.operation_id)
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn close_stdin(&self, request: CloseStdinRequest) -> Result<()> {
        let lifecycle = self.lifecycle("close-stdin")?;
        lifecycle.ensure_operation(RuntimeOperation::CloseStdin, "close-stdin")?;
        let target = match lifecycle.store.prepare_close_stdin(&request).await? {
            ProcessIoPreparation::Replayed => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(()))
                    .await;
            }
            ProcessIoPreparation::Prepared(target) | ProcessIoPreparation::Resume(target) => target,
        };
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "close-stdin")?;
        registered.ensure_operation(RuntimeOperation::CloseStdin, "close-stdin")?;
        lifecycle.driver_boundary(DriverOperation::CloseStdin, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .close_stdin(DriverCloseStdinRequest {
                context: request.context.clone(),
                target,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::CloseStdin, DriverBoundaryStage::AfterCall)?;
        if let Err(error) = result {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let completed = lifecycle
            .store
            .complete_close_stdin(&request.context.operation_id)
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn resize(&self, request: ResizeRequest) -> Result<()> {
        let lifecycle = self.lifecycle("resize")?;
        lifecycle.ensure_operation(RuntimeOperation::Resize, "resize")?;
        let target = match lifecycle.store.prepare_resize(&request).await? {
            ProcessIoPreparation::Replayed => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(()))
                    .await;
            }
            ProcessIoPreparation::Prepared(target) | ProcessIoPreparation::Resume(target) => target,
        };
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "resize")?;
        registered.ensure_operation(RuntimeOperation::Resize, "resize")?;
        lifecycle.driver_boundary(DriverOperation::Resize, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .resize(DriverResizeRequest {
                context: request.context.clone(),
                target,
                size: request.size,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Resize, DriverBoundaryStage::AfterCall)?;
        if let Err(error) = result {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let completed = lifecycle
            .store
            .complete_resize(&request.context.operation_id)
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn signal_process(&self, request: SignalProcessRequest) -> Result<()> {
        let lifecycle = self.lifecycle("signal-process")?;
        lifecycle.ensure_operation(RuntimeOperation::SignalProcess, "signal-process")?;
        let target = match lifecycle.store.prepare_signal_process(&request).await? {
            SignalProcessPreparation::Replayed => {
                return lifecycle
                    .acknowledge_result(&request.context.operation_id, Ok(()))
                    .await;
            }
            SignalProcessPreparation::Prepared(target)
            | SignalProcessPreparation::Resume(target) => target,
        };
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "signal-process")?;
        registered.ensure_operation(RuntimeOperation::SignalProcess, "signal-process")?;
        lifecycle.driver_boundary(
            DriverOperation::SignalProcess,
            DriverBoundaryStage::BeforeCall,
        )?;
        let result = registered
            .driver()
            .signal_process(DriverSignalProcessRequest {
                context: request.context.clone(),
                target,
                signal: request.signal,
            })
            .await;
        lifecycle.driver_boundary(
            DriverOperation::SignalProcess,
            DriverBoundaryStage::AfterCall,
        )?;
        if let Err(error) = result {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let completed = lifecycle
            .store
            .complete_signal_process(&request.context.operation_id)
            .await;
        lifecycle
            .acknowledge_result(&request.context.operation_id, completed)
            .await
    }

    async fn wait_process(&self, request: WaitProcessRequest) -> Result<ExitStatus> {
        let lifecycle = self.lifecycle("wait-process")?;
        lifecycle.ensure_operation(RuntimeOperation::WaitProcess, "wait-process")?;
        let target = match lifecycle.store.prepare_wait_process(&request).await? {
            ProcessWaitPreparation::Replayed(status) => return Ok(status),
            ProcessWaitPreparation::Prepared(target) => target,
        };
        let container = lifecycle.store.state(&target.container).await?;
        let registered = lifecycle.driver(container.driver, "wait-process")?;
        registered.ensure_operation(RuntimeOperation::WaitProcess, "wait-process")?;
        lifecycle.driver_boundary(
            DriverOperation::WaitProcess,
            DriverBoundaryStage::BeforeCall,
        )?;
        let result = registered
            .driver()
            .wait_process(DriverWaitProcessRequest {
                target: target.clone(),
                timeout_ms: request.timeout_ms,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::WaitProcess, DriverBoundaryStage::AfterCall)?;
        let status = result?;
        status.validate()?;
        lifecycle.complete_process_wait(&target, status).await
    }

    async fn file(&self, mut request: FileRequest) -> Result<FileResponse> {
        let lifecycle = self.lifecycle("file")?;
        lifecycle.ensure_operation(RuntimeOperation::File, "file")?;
        request.validate()?;
        if request.op == FileOp::Upload {
            let operation_id = request
                .context
                .as_ref()
                .expect("validated File upload has an operation context")
                .operation_id
                .clone();
            let expected_upload_size = request
                .data
                .as_deref()
                .map(|data| STANDARD.decode(data))
                .transpose()
                .map_err(|error| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("file upload data is not valid base64: {error}"),
                    )
                    .for_operation("file")
                })?
                .map(|data| data.len() as u64);
            let target = match lifecycle.store.prepare_file_mutation(&request).await? {
                FilesystemMutationPreparation::Replayed(response) => {
                    return lifecycle
                        .acknowledge_result(&operation_id, Ok(response))
                        .await;
                }
                FilesystemMutationPreparation::Prepared(target)
                | FilesystemMutationPreparation::Resume(target) => target,
            };
            let record = lifecycle.store.state(&target).await?;
            let registered = lifecycle.driver(record.driver, "file")?;
            registered.ensure_operation(RuntimeOperation::File, "file")?;
            request.target = target.clone();
            lifecycle.driver_boundary(DriverOperation::File, DriverBoundaryStage::BeforeCall)?;
            let result = registered.driver().file(request).await;
            lifecycle.driver_boundary(DriverOperation::File, DriverBoundaryStage::AfterCall)?;
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    return lifecycle.fail_driver_operation(&operation_id, error).await;
                }
            };
            if let Err(error) =
                validate_file_response(&response, &target, FileOp::Upload, expected_upload_size)
            {
                return lifecycle.fail_driver_operation(&operation_id, error).await;
            }
            let completed = lifecycle
                .store
                .complete_file_mutation(&operation_id, response)
                .await;
            return lifecycle.acknowledge_result(&operation_id, completed).await;
        }

        let record = lifecycle.store.state(&request.target).await?;
        ensure_live_filesystem(&record, "file")?;
        let registered = lifecycle.driver(record.driver, "file")?;
        registered.ensure_operation(RuntimeOperation::File, "file")?;
        request.target = ContainerTarget::exact(request.target.id, record.generation);
        let expected_target = request.target.clone();
        let operation = request.op;
        lifecycle.driver_boundary(DriverOperation::File, DriverBoundaryStage::BeforeCall)?;
        let result = registered.driver().file(request).await;
        lifecycle.driver_boundary(DriverOperation::File, DriverBoundaryStage::AfterCall)?;
        let response = result?;
        validate_file_response(&response, &expected_target, operation, None)?;
        Ok(response)
    }

    async fn filesystem(&self, mut request: FilesystemRequest) -> Result<FilesystemResponse> {
        let lifecycle = self.lifecycle("filesystem")?;
        lifecycle.ensure_operation(RuntimeOperation::Filesystem, "filesystem")?;
        request.validate()?;
        if request.op.is_mutating() {
            let operation_id = request
                .context
                .as_ref()
                .expect("validated Filesystem mutation has an operation context")
                .operation_id
                .clone();
            let operation = request.op;
            let target = match lifecycle
                .store
                .prepare_filesystem_mutation(&request)
                .await?
            {
                FilesystemMutationPreparation::Replayed(response) => {
                    return lifecycle
                        .acknowledge_result(&operation_id, Ok(response))
                        .await;
                }
                FilesystemMutationPreparation::Prepared(target)
                | FilesystemMutationPreparation::Resume(target) => target,
            };
            let record = lifecycle.store.state(&target).await?;
            let registered = lifecycle.driver(record.driver, "filesystem")?;
            registered.ensure_operation(RuntimeOperation::Filesystem, "filesystem")?;
            request.target = target.clone();
            lifecycle
                .driver_boundary(DriverOperation::Filesystem, DriverBoundaryStage::BeforeCall)?;
            let result = registered.driver().filesystem(request).await;
            lifecycle
                .driver_boundary(DriverOperation::Filesystem, DriverBoundaryStage::AfterCall)?;
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    return lifecycle.fail_driver_operation(&operation_id, error).await;
                }
            };
            if let Err(error) = validate_filesystem_response(&response, &target, operation) {
                return lifecycle.fail_driver_operation(&operation_id, error).await;
            }
            let completed = lifecycle
                .store
                .complete_filesystem_mutation(&operation_id, response)
                .await;
            return lifecycle.acknowledge_result(&operation_id, completed).await;
        }

        let record = lifecycle.store.state(&request.target).await?;
        ensure_live_filesystem(&record, "filesystem")?;
        let registered = lifecycle.driver(record.driver, "filesystem")?;
        registered.ensure_operation(RuntimeOperation::Filesystem, "filesystem")?;
        request.target = ContainerTarget::exact(request.target.id, record.generation);
        let expected_target = request.target.clone();
        let operation = request.op;
        lifecycle.driver_boundary(DriverOperation::Filesystem, DriverBoundaryStage::BeforeCall)?;
        let result = registered.driver().filesystem(request).await;
        lifecycle.driver_boundary(DriverOperation::Filesystem, DriverBoundaryStage::AfterCall)?;
        let response = result?;
        validate_filesystem_response(&response, &expected_target, operation)?;
        Ok(response)
    }

    async fn checkpoint(&self, _request: CheckpointRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("checkpoint"))
    }

    async fn restore(&self, _request: RestoreRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("restore"))
    }
}

fn ensure_live_filesystem(record: &ContainerRecord, operation: &'static str) -> Result<()> {
    if matches!(
        record.state.status(),
        ContainerState::Created | ContainerState::Running
    ) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "container {} generation {:?} cannot serve {operation} while {}",
                record.state.id(),
                record.generation,
                record.state.status()
            ),
        )
        .for_operation(operation))
    }
}

fn validate_file_response(
    response: &FileResponse,
    expected_target: &ContainerTarget,
    operation: FileOp,
    expected_upload_size: Option<u64>,
) -> Result<()> {
    if &response.target != expected_target {
        return Err(Error::new(
            ErrorCode::Conflict,
            "runtime driver returned a file response for a different container generation",
        )
        .for_operation("file"));
    }
    if response.size > MAX_FILE_TRANSFER_BYTES as u64 {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!(
                "runtime driver returned a {}-byte file; maximum is {MAX_FILE_TRANSFER_BYTES}",
                response.size
            ),
        )
        .for_operation("file"));
    }
    match operation {
        FileOp::Upload => {
            if response.data.is_some() || Some(response.size) != expected_upload_size {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "runtime driver returned an invalid upload acknowledgement",
                )
                .for_operation("file"));
            }
        }
        FileOp::Download => {
            let data = response.data.as_deref().ok_or_else(|| {
                Error::new(
                    ErrorCode::Conflict,
                    "runtime driver omitted the downloaded file payload",
                )
                .for_operation("file")
            })?;
            let decoded = STANDARD.decode(data).map_err(|error| {
                Error::new(
                    ErrorCode::Conflict,
                    format!("runtime driver returned invalid base64 file data: {error}"),
                )
                .for_operation("file")
            })?;
            if decoded.len() as u64 != response.size {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "runtime driver file size does not match its decoded payload",
                )
                .for_operation("file"));
            }
        }
    }
    Ok(())
}

fn validate_filesystem_response(
    response: &FilesystemResponse,
    expected_target: &ContainerTarget,
    operation: FilesystemOp,
) -> Result<()> {
    const MAX_ENTRIES: usize = 4_096;
    const MAX_RESPONSE_BYTES: usize = 12 * 1024 * 1024;
    if &response.target != expected_target {
        return Err(Error::new(
            ErrorCode::Conflict,
            "runtime driver returned filesystem data for a different container generation",
        )
        .for_operation("filesystem"));
    }
    let shape_is_valid = match operation {
        FilesystemOp::Stat | FilesystemOp::MakeDir | FilesystemOp::Move => {
            response.entry.is_some() && response.entries.is_empty()
        }
        FilesystemOp::ListDir => response.entry.is_none(),
        FilesystemOp::Remove => response.entry.is_none() && response.entries.is_empty(),
    };
    if !shape_is_valid {
        return Err(Error::new(
            ErrorCode::Conflict,
            "runtime driver returned an invalid filesystem response shape",
        )
        .for_operation("filesystem"));
    }
    if response.entries.len() > MAX_ENTRIES {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!("runtime driver returned more than {MAX_ENTRIES} filesystem entries"),
        )
        .for_operation("filesystem"));
    }
    let encoded = serde_json::to_vec(response).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to size runtime filesystem response: {error}"),
        )
        .for_operation("filesystem")
    })?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!("runtime filesystem response exceeds {MAX_RESPONSE_BYTES} bytes"),
        )
        .for_operation("filesystem"));
    }
    Ok(())
}

fn validate_output_chunks(
    chunks: &[OutputChunk],
    after_sequence: u64,
    max_bytes: u32,
) -> Result<()> {
    let mut previous = after_sequence;
    let mut total = 0_u64;
    for chunk in chunks {
        if !chunk.eof && chunk.data.is_empty() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "runtime driver returned an empty process output data chunk",
            )
            .for_operation("read-output"));
        }
        if chunk.eof && !chunk.data.is_empty() {
            return Err(Error::new(
                ErrorCode::Internal,
                "runtime driver returned output data in an EOF chunk",
            )
            .for_operation("read-output"));
        }
        let width = if chunk.eof {
            1
        } else {
            u64::try_from(chunk.data.len()).map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "runtime driver output chunk length does not fit its sequence cursor",
                )
                .for_operation("read-output")
            })?
        };
        let expected = previous.checked_add(width).ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "runtime driver output sequence space is exhausted",
            )
            .for_operation("read-output")
        })?;
        if chunk.sequence != expected {
            return Err(Error::new(
                ErrorCode::Conflict,
                "runtime driver returned a non-contiguous process output byte cursor",
            )
            .for_operation("read-output"));
        }
        total = total.checked_add(chunk.data.len() as u64).ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "runtime driver output byte count overflowed",
            )
            .for_operation("read-output")
        })?;
        previous = chunk.sequence;
    }
    if total > u64::from(max_bytes) {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!("runtime driver returned {total} bytes for a {max_bytes}-byte output poll"),
        )
        .for_operation("read-output"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
