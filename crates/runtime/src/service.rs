use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{CapabilityStatus, DriverCapability, RuntimeFeatures};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, FeaturesBuilder};
use a3s_oci_sdk::{
    async_trait, CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, ContainerTarget, CreateRequest, DeleteRequest, Error, ErrorCode, EventBatch,
    EventsRequest, ExecRequest, ExitStatus, KillRequest, ListRequest, OciRuntimeService,
    OutputChunk, ProcessRecord, ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest,
    Result, RuntimeInfo, RuntimeOperation, SignalProcessRequest, StartRequest, StateRequest,
    StatsRequest, UpdateRequest, ValidateRequest, WaitProcessRequest, WaitRequest,
    WriteStdinRequest, OCI_RUNTIME_SPEC_VERSION_MAX, OCI_RUNTIME_SPEC_VERSION_MIN,
};

use crate::driver::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, RuntimeDriver,
};
use crate::state::{DeletePreparation, DurableStateStore, RecordOperationPreparation};

/// In-process host implementation used by the CLI and A3S Box adapter.
#[derive(Clone, Default)]
pub struct HostRuntimeService {
    lifecycle: Option<Arc<LifecycleHost>>,
}

struct LifecycleHost {
    store: DurableStateStore,
    driver: Arc<dyn RuntimeDriver>,
    capability: DriverCapability,
}

impl fmt::Debug for HostRuntimeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRuntimeService")
            .field(
                "driver",
                &self
                    .lifecycle
                    .as_ref()
                    .map(|lifecycle| lifecycle.capability.driver),
            )
            .finish()
    }
}

impl HostRuntimeService {
    /// Construct the probe-only local host service.
    #[must_use]
    pub const fn new() -> Self {
        Self { lifecycle: None }
    }

    /// Open durable lifecycle orchestration around one fully enforcing driver.
    pub async fn open(
        state_root: impl AsRef<Path>,
        driver: Arc<dyn RuntimeDriver>,
    ) -> Result<Self> {
        let capability = driver.capability();
        if !capability.can_launch() {
            let code = if capability.status == CapabilityStatus::Unavailable {
                ErrorCode::Unavailable
            } else {
                ErrorCode::Unsupported
            };
            return Err(Error::new(
                code,
                format!(
                    "driver {:?} is not launch-ready: status {:?}, readiness {:?}",
                    capability.driver, capability.status, capability.readiness
                ),
            )
            .for_operation("open-host-runtime"));
        }
        if capability.isolation_classes.is_empty() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "launch-ready driver {:?} advertises no isolation class",
                    capability.driver
                ),
            )
            .for_operation("open-host-runtime"));
        }
        let store = DurableStateStore::open(state_root).await?;
        Ok(Self {
            lifecycle: Some(Arc::new(LifecycleHost {
                store,
                driver,
                capability,
            })),
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
            if let Some(existing) = features
                .drivers
                .iter_mut()
                .find(|entry| entry.driver == lifecycle.capability.driver)
            {
                *existing = lifecycle.capability.clone();
            } else {
                features.drivers.push(lifecycle.capability.clone());
            }
        }
        features
    }
}

impl LifecycleHost {
    fn ensure_isolation(&self, request: &CreateRequest) -> Result<()> {
        let isolation = request.isolation.class();
        if self.capability.isolation_classes.contains(&isolation) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "driver {:?} does not provide requested isolation {isolation:?}",
                    self.capability.driver
                ),
            )
            .for_operation("create"))
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
        let annotations = HashMap::from([
            (
                "dev.a3s.oci.runtime.version".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            ),
            (
                "dev.a3s.oci.runtime.lifecycle".to_string(),
                if self.lifecycle.is_some() {
                    "durable-core"
                } else {
                    "probe-only"
                }
                .to_string(),
            ),
        ]);
        let oci = FeaturesBuilder::default()
            .oci_version_min(OCI_RUNTIME_SPEC_VERSION_MIN)
            .oci_version_max(OCI_RUNTIME_SPEC_VERSION_MAX)
            .hooks(Vec::<String>::new())
            .mount_options(Vec::<String>::new())
            .annotations(annotations)
            .build()
            .map_err(|error| {
                Error::new(
                    ErrorCode::Internal,
                    format!("failed to construct OCI feature report: {error}"),
                )
                .for_operation("features")
            })?;

        let operations = if self.lifecycle.is_some() {
            vec![
                RuntimeOperation::Features,
                RuntimeOperation::Create,
                RuntimeOperation::State,
                RuntimeOperation::Start,
                RuntimeOperation::Kill,
                RuntimeOperation::Delete,
            ]
        } else {
            vec![RuntimeOperation::Features]
        };
        Ok(RuntimeInfo {
            oci,
            drivers: self.runtime_features(),
            operations,
        })
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("create")?;
        lifecycle.ensure_isolation(&request)?;
        let prepared = lifecycle
            .store
            .prepare_create(&request, lifecycle.capability.driver)
            .await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.id.clone(), record.generation);
        let durable_bundle = lifecycle.store.bundle(&target).await?;
        let observed = match lifecycle
            .driver
            .create(DriverCreateRequest {
                context: request.context.clone(),
                target,
                bundle: durable_bundle,
                isolation: request.isolation,
                io: request.io,
            })
            .await
        {
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

    async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("state")?;
        request.validate()?;
        let durable = lifecycle.store.state(&request.target).await?;
        if *durable.state.status() == ContainerState::Creating {
            return Ok(durable);
        }
        let target = ContainerTarget::exact(request.target.id, durable.generation);
        let observed = lifecycle.driver.state(target.clone()).await?;
        lifecycle
            .store
            .observe_state(&target, observed.status(), observed.pid())
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
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        let bundle = lifecycle.store.bundle(&target).await?;
        let observed = match lifecycle
            .driver
            .start(DriverStartRequest {
                context: request.context.clone(),
                target,
                bundle,
            })
            .await
        {
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
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        let observed = match lifecycle
            .driver
            .kill(DriverKillRequest {
                context: request.context.clone(),
                target,
                signal: request.signal,
                all: request.all,
            })
            .await
        {
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
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if let Err(error) = lifecycle
            .driver
            .delete(DriverDeleteRequest {
                context: request.context.clone(),
                target,
                mode: request.mode,
            })
            .await
        {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        lifecycle
            .store
            .complete_delete(&request.context.operation_id)
            .await
    }

    async fn exec(&self, _request: ExecRequest) -> Result<ProcessRecord> {
        Err(Error::unsupported("exec"))
    }

    async fn wait(&self, _request: WaitRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("wait"))
    }

    async fn list(&self, _request: ListRequest) -> Result<Vec<ContainerRecord>> {
        Err(Error::unsupported("list"))
    }

    async fn pause(&self, _request: ContainerOperationRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("pause"))
    }

    async fn resume(&self, _request: ContainerOperationRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("resume"))
    }

    async fn update(&self, _request: UpdateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("update"))
    }

    async fn processes(&self, _request: ProcessesRequest) -> Result<Vec<ProcessRecord>> {
        Err(Error::unsupported("processes"))
    }

    async fn stats(&self, _request: StatsRequest) -> Result<ContainerStats> {
        Err(Error::unsupported("stats"))
    }

    async fn events(&self, _request: EventsRequest) -> Result<EventBatch> {
        Err(Error::unsupported("events"))
    }

    async fn read_output(&self, _request: ReadOutputRequest) -> Result<Vec<OutputChunk>> {
        Err(Error::unsupported("read-output"))
    }

    async fn write_stdin(&self, _request: WriteStdinRequest) -> Result<()> {
        Err(Error::unsupported("write-stdin"))
    }

    async fn close_stdin(&self, _request: CloseStdinRequest) -> Result<()> {
        Err(Error::unsupported("close-stdin"))
    }

    async fn resize(&self, _request: ResizeRequest) -> Result<()> {
        Err(Error::unsupported("resize"))
    }

    async fn signal_process(&self, _request: SignalProcessRequest) -> Result<()> {
        Err(Error::unsupported("signal-process"))
    }

    async fn wait_process(&self, _request: WaitProcessRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("wait-process"))
    }

    async fn checkpoint(&self, _request: CheckpointRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("checkpoint"))
    }

    async fn restore(&self, _request: RestoreRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("restore"))
    }
}

#[cfg(test)]
mod tests;
