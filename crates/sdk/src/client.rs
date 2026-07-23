use std::sync::Arc;

use crate::{
    CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, CreateRequest, DeleteRequest, EventBatch, EventsRequest, ExecRequest,
    ExitStatus, KillRequest, ListRequest, OciRuntimeService, OutputChunk, ProcessRecord,
    ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest, Result, RuntimeInfo,
    SignalProcessRequest, StartRequest, StateRequest, StatsRequest, UpdateRequest,
    WaitProcessRequest, WaitRequest, WriteStdinRequest,
};

/// Cloneable, transport-independent Rust SDK client.
#[derive(Clone)]
pub struct RuntimeClient {
    service: Arc<dyn OciRuntimeService>,
}

impl RuntimeClient {
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
        self.service.create(request).await
    }

    pub async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        self.service.state(request).await
    }

    pub async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        self.service.start(request).await
    }

    pub async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        self.service.kill(request).await
    }

    pub async fn delete(&self, request: DeleteRequest) -> Result<()> {
        self.service.delete(request).await
    }

    pub async fn exec(&self, request: ExecRequest) -> Result<ProcessRecord> {
        self.service.exec(request).await
    }

    pub async fn wait(&self, request: WaitRequest) -> Result<ExitStatus> {
        self.service.wait(request).await
    }

    pub async fn list(&self, request: ListRequest) -> Result<Vec<ContainerRecord>> {
        self.service.list(request).await
    }

    pub async fn pause(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        self.service.pause(request).await
    }

    pub async fn resume(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        self.service.resume(request).await
    }

    pub async fn update(&self, request: UpdateRequest) -> Result<ContainerRecord> {
        self.service.update(request).await
    }

    pub async fn processes(&self, request: ProcessesRequest) -> Result<Vec<ProcessRecord>> {
        self.service.processes(request).await
    }

    pub async fn stats(&self, request: StatsRequest) -> Result<ContainerStats> {
        self.service.stats(request).await
    }

    pub async fn events(&self, request: EventsRequest) -> Result<EventBatch> {
        self.service.events(request).await
    }

    pub async fn read_output(&self, request: ReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.service.read_output(request).await
    }

    pub async fn write_stdin(&self, request: WriteStdinRequest) -> Result<()> {
        self.service.write_stdin(request).await
    }

    pub async fn close_stdin(&self, request: CloseStdinRequest) -> Result<()> {
        self.service.close_stdin(request).await
    }

    pub async fn resize(&self, request: ResizeRequest) -> Result<()> {
        self.service.resize(request).await
    }

    pub async fn signal_process(&self, request: SignalProcessRequest) -> Result<()> {
        self.service.signal_process(request).await
    }

    pub async fn wait_process(&self, request: WaitProcessRequest) -> Result<ExitStatus> {
        self.service.wait_process(request).await
    }

    pub async fn checkpoint(&self, request: CheckpointRequest) -> Result<ContainerRecord> {
        self.service.checkpoint(request).await
    }

    pub async fn restore(&self, request: RestoreRequest) -> Result<ContainerRecord> {
        self.service.restore(request).await
    }
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
