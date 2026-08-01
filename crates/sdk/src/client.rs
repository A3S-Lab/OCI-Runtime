use std::sync::Arc;

use crate::oci_spec::runtime::ContainerState;
use crate::{
    CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    EventBatch, EventsRequest, ExecRequest, ExitStatus, KillRequest, ListRequest, LocalIpcEndpoint,
    OciRuntimeService, OutputChunk, ProcessRecord, ProcessesRequest, ReadOutputRequest,
    ResizeRequest, RestoreRequest, Result, RunRequest, RuntimeInfo, RuntimeTransportClient,
    SignalProcessRequest, StartRequest, StateRequest, StatsRequest, UpdateRequest, ValidateRequest,
    WaitProcessRequest, WaitRequest, WriteStdinRequest,
};

/// Cloneable, transport-independent Rust SDK client.
#[derive(Clone)]
pub struct RuntimeClient {
    service: Arc<dyn OciRuntimeService>,
}

impl RuntimeClient {
    /// Connect to an out-of-process runtime over a validated local IPC endpoint.
    ///
    /// A request that observes a broken connection returns that ambiguity to
    /// the caller and is never replayed inside the transport. A later explicit
    /// call reconnects to the same endpoint and negotiates a fresh stream, so
    /// operation-aware callers can retry with the same durable identity.
    pub async fn connect(endpoint: &LocalIpcEndpoint) -> Result<Self> {
        Ok(Self::new(RuntimeTransportClient::connect(endpoint).await?))
    }

    /// Wrap an in-process or transported runtime service.
    #[must_use]
    pub fn new(service: impl OciRuntimeService + 'static) -> Self {
        Self {
            service: Arc::new(service),
        }
    }

    /// Wrap an existing shared runtime service.
    #[must_use]
    pub const fn from_arc(service: Arc<dyn OciRuntimeService>) -> Self {
        Self { service }
    }

    pub async fn features(&self) -> Result<RuntimeInfo> {
        self.service.features().await
    }

    pub async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.create(request).await
    }

    /// Run one foreground container by composing the normal OCI lifecycle.
    ///
    /// Once create succeeds, the SDK always submits the same force-delete
    /// request before returning, including when start or wait fails. This
    /// prevents the convenience operation from creating a second lifecycle
    /// or leaving ownership of partial cleanup ambiguous.
    pub async fn run(&self, request: RunRequest) -> Result<ExitStatus> {
        request.validate()?;
        let RunRequest {
            create,
            start_context,
            delete_context,
        } = request;
        let expected_id = create.id.clone();
        let created = self.create(create).await?;
        let target = ContainerTarget::exact(expected_id, created.generation);

        let lifecycle = async {
            validate_run_record(&created, &target, ContainerState::Created, "create")?;
            let started = self
                .start(StartRequest {
                    context: start_context,
                    target: target.clone(),
                })
                .await?;
            validate_run_record(&started, &target, ContainerState::Running, "start")?;
            let status = self
                .wait(WaitRequest {
                    target: target.clone(),
                    timeout_ms: None,
                })
                .await?;
            status.validate()?;
            Ok(status)
        }
        .await;

        let cleanup = self
            .delete(DeleteRequest {
                context: delete_context,
                target,
                mode: DeleteMode::Force,
            })
            .await;
        match (lifecycle, cleanup) {
            (Ok(status), Ok(())) => Ok(status),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(primary), Err(cleanup)) => Err(combine_run_errors(primary, cleanup)),
        }
    }

    pub async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.state(request).await
    }

    pub async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.start(request).await
    }

    pub async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.kill(request).await
    }

    pub async fn delete(&self, request: DeleteRequest) -> Result<()> {
        request.validate()?;
        self.service.delete(request).await
    }

    pub async fn exec(&self, request: ExecRequest) -> Result<ProcessRecord> {
        request.validate()?;
        self.service.exec(request).await
    }

    pub async fn wait(&self, request: WaitRequest) -> Result<ExitStatus> {
        request.validate()?;
        self.service.wait(request).await
    }

    pub async fn list(&self, request: ListRequest) -> Result<Vec<ContainerRecord>> {
        request.validate()?;
        self.service.list(request).await
    }

    pub async fn pause(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.pause(request).await
    }

    pub async fn resume(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.resume(request).await
    }

    pub async fn update(&self, request: UpdateRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.update(request).await
    }

    pub async fn processes(&self, request: ProcessesRequest) -> Result<Vec<ProcessRecord>> {
        request.validate()?;
        self.service.processes(request).await
    }

    pub async fn stats(&self, request: StatsRequest) -> Result<ContainerStats> {
        request.validate()?;
        self.service.stats(request).await
    }

    pub async fn events(&self, request: EventsRequest) -> Result<EventBatch> {
        request.validate()?;
        self.service.events(request).await
    }

    pub async fn read_output(&self, request: ReadOutputRequest) -> Result<Vec<OutputChunk>> {
        request.validate()?;
        self.service.read_output(request).await
    }

    pub async fn write_stdin(&self, request: WriteStdinRequest) -> Result<()> {
        request.validate()?;
        self.service.write_stdin(request).await
    }

    pub async fn close_stdin(&self, request: CloseStdinRequest) -> Result<()> {
        request.validate()?;
        self.service.close_stdin(request).await
    }

    pub async fn resize(&self, request: ResizeRequest) -> Result<()> {
        request.validate()?;
        self.service.resize(request).await
    }

    pub async fn signal_process(&self, request: SignalProcessRequest) -> Result<()> {
        request.validate()?;
        self.service.signal_process(request).await
    }

    pub async fn wait_process(&self, request: WaitProcessRequest) -> Result<ExitStatus> {
        request.validate()?;
        self.service.wait_process(request).await
    }

    pub async fn checkpoint(&self, request: CheckpointRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.checkpoint(request).await
    }

    pub async fn restore(&self, request: RestoreRequest) -> Result<ContainerRecord> {
        request.validate()?;
        self.service.restore(request).await
    }
}

fn validate_run_record(
    record: &ContainerRecord,
    target: &ContainerTarget,
    expected_status: ContainerState,
    operation: &str,
) -> Result<()> {
    let generation = target.generation.ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "run constructed a non-exact lifecycle target",
        )
        .for_operation("run")
    })?;
    if record.state.id() == target.id.as_str()
        && record.generation == generation
        && *record.state.status() == expected_status
    {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::Conflict,
        format!(
            "run {operation} returned container {} generation {} in state {}; expected {} generation {} in state {expected_status}",
            record.state.id(),
            record.generation.0,
            record.state.status(),
            target.id,
            generation.0,
        ),
    )
    .for_operation("run"))
}

fn combine_run_errors(mut primary: Error, cleanup: Error) -> Error {
    primary.message = format!(
        "{}; forced run cleanup also failed during {}: {}",
        primary.message,
        cleanup.operation.as_deref().unwrap_or("delete"),
        cleanup.message,
    );
    primary.retryable |= cleanup.retryable;
    primary
}

#[cfg(test)]
mod tests {
    use super::RuntimeClient;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn client_is_send_sync() {
        assert_send_sync::<RuntimeClient>();
    }
}
