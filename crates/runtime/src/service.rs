use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{DriverKind, RuntimeFeatures};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, CheckpointRequest, CloseStdinRequest, ContainerId,
    ContainerOperationRequest, ContainerRecord, ContainerStats, ContainerTarget, CreateRequest,
    DeleteRequest, Error, ErrorCode, EventBatch, EventsRequest, ExecRequest, ExitStatus,
    KillRequest, ListRequest, OciRuntimeService, OutputChunk, ProcessId, ProcessRecord,
    ProcessTarget, ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest, Result,
    RuntimeInfo, RuntimeOperation, SignalProcessRequest, StartRequest, StateRequest, StatsRequest,
    UpdateRequest, ValidateRequest, WaitProcessRequest, WaitRequest, WriteStdinRequest,
};

use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateAttachments,
    DriverCreateRequest, DriverDeleteRequest, DriverExecRequest, DriverKillRequest,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest, DriverWriteStdinRequest,
    RuntimeDriver,
};
use crate::fault::{
    DriverBoundaryStage, DriverOperation, FaultInjector, FaultPoint, NoFaultInjector,
};
use crate::state::{
    DeletePreparation, DurableStateStore, ProcessIoPreparation, ProcessOperationPreparation,
    ProcessWaitPreparation, RecordOperationPreparation, SignalProcessPreparation,
};

mod driver_registry;
mod feature_report;

use driver_registry::{DriverRegistration, DriverRegistry, RegisteredDriver};

#[cfg(test)]
use feature_report::{RECOGNIZED_LINUX_MOUNT_OPTIONS, SUPPORTED_LINUX_CAPABILITIES};

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
            let target =
                ContainerTarget::exact(ContainerId::new(record.state.id())?, record.generation);
            let (observation, init_exit_status) = recovery.into_parts();
            if let Some(observation) = observation {
                store
                    .observe_state_with_pause(
                        &target,
                        observation.status(),
                        observation.pid(),
                        observation.paused(),
                    )
                    .await?;
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
        AttachmentCapabilities::base_v1().require(&request.attachments)?;
        let lifecycle = self.lifecycle("create")?;
        let registered = lifecycle
            .drivers
            .select(request.isolation.class(), "create")?;
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
            RecordOperationPreparation::Replayed(record) => return Ok(record),
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.id.clone(), record.generation);
        let durable_bundle = lifecycle.store.bundle(&target).await?;
        lifecycle.driver_boundary(DriverOperation::Create, DriverBoundaryStage::BeforeCall)?;
        let result = registered
            .driver()
            .create(DriverCreateRequest {
                context: request.context.clone(),
                target,
                bundle: durable_bundle,
                isolation: request.isolation,
                io: request.attachments.process_io().clone(),
                attachment_contract: request.attachments,
                attachments,
            })
            .await;
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
        lifecycle
            .store
            .complete_create(&request.context.operation_id, pid)
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
        Err(error)
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
        let oci = feature_report::build(self.lifecycle.is_some(), hooks)?;

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
            attachments: AttachmentCapabilities::base_v1(),
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
            RecordOperationPreparation::Replayed(record) => return Ok(record),
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
        lifecycle
            .store
            .complete_start(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
            )
            .await
    }

    async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("kill")?;
        let prepared = lifecycle.store.prepare_kill(&request).await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
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
        lifecycle
            .store
            .complete_kill(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
            )
            .await
    }

    async fn delete(&self, request: DeleteRequest) -> Result<()> {
        let lifecycle = self.lifecycle("delete")?;
        let prepared = lifecycle.store.prepare_delete(&request).await?;
        let record = match prepared {
            DeletePreparation::Replayed => return Ok(()),
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
        lifecycle
            .store
            .complete_delete(&request.context.operation_id)
            .await
    }

    async fn exec(&self, request: ExecRequest) -> Result<ProcessRecord> {
        let lifecycle = self.lifecycle("exec")?;
        lifecycle.ensure_operation(RuntimeOperation::Exec, "exec")?;
        let prepared = lifecycle.store.prepare_exec(&request).await?;
        let durable = match prepared {
            ProcessOperationPreparation::Replayed(record) => return Ok(record),
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
        lifecycle
            .store
            .complete_exec(
                &request.context.operation_id,
                process.pid(),
                process.terminal(),
            )
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
            RecordOperationPreparation::Replayed(record) => return Ok(record),
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
        lifecycle
            .store
            .complete_pause(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await
    }

    async fn resume(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("resume")?;
        lifecycle.ensure_operation(RuntimeOperation::Resume, "resume")?;
        let record = match lifecycle.store.prepare_resume(&request).await? {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
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
        lifecycle
            .store
            .complete_resume(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await
    }

    async fn update(&self, request: UpdateRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("update")?;
        lifecycle.ensure_operation(RuntimeOperation::Update, "update")?;
        let record = match lifecycle.store.prepare_update(&request).await? {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
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
        lifecycle
            .store
            .complete_update(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
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
            ProcessIoPreparation::Replayed => return Ok(()),
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
        lifecycle
            .store
            .complete_write_stdin(&request.context.operation_id)
            .await
    }

    async fn close_stdin(&self, request: CloseStdinRequest) -> Result<()> {
        let lifecycle = self.lifecycle("close-stdin")?;
        lifecycle.ensure_operation(RuntimeOperation::CloseStdin, "close-stdin")?;
        let target = match lifecycle.store.prepare_close_stdin(&request).await? {
            ProcessIoPreparation::Replayed => return Ok(()),
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
        lifecycle
            .store
            .complete_close_stdin(&request.context.operation_id)
            .await
    }

    async fn resize(&self, request: ResizeRequest) -> Result<()> {
        let lifecycle = self.lifecycle("resize")?;
        lifecycle.ensure_operation(RuntimeOperation::Resize, "resize")?;
        let target = match lifecycle.store.prepare_resize(&request).await? {
            ProcessIoPreparation::Replayed => return Ok(()),
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
        lifecycle
            .store
            .complete_resize(&request.context.operation_id)
            .await
    }

    async fn signal_process(&self, request: SignalProcessRequest) -> Result<()> {
        let lifecycle = self.lifecycle("signal-process")?;
        lifecycle.ensure_operation(RuntimeOperation::SignalProcess, "signal-process")?;
        let target = match lifecycle.store.prepare_signal_process(&request).await? {
            SignalProcessPreparation::Replayed => return Ok(()),
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
        lifecycle
            .store
            .complete_signal_process(&request.context.operation_id)
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

    async fn checkpoint(&self, _request: CheckpointRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("checkpoint"))
    }

    async fn restore(&self, _request: RestoreRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("restore"))
    }
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
