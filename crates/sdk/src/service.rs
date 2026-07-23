use async_trait::async_trait;

use crate::{
    CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, CreateRequest, DeleteRequest, Error, EventBatch, EventsRequest, ExecRequest,
    ExitStatus, KillRequest, ListRequest, OutputChunk, ProcessRecord, ProcessesRequest,
    ReadOutputRequest, ResizeRequest, RestoreRequest, Result, RuntimeInfo, SignalProcessRequest,
    StartRequest, StateRequest, StatsRequest, UpdateRequest, WaitProcessRequest, WaitRequest,
    WriteStdinRequest,
};

/// Complete asynchronous runtime contract consumed by [`crate::RuntimeClient`].
///
/// Implementations may be in-process, a local IPC transport, or the host side
/// of a guest-agent protocol. Every method must preserve the same typed
/// semantics and stable error classes.
#[async_trait]
pub trait OciRuntimeService: Send + Sync {
    /// Discover OCI and driver capabilities.
    async fn features(&self) -> Result<RuntimeInfo>;

    /// Perform the OCI create operation without executing `process.args`.
    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord>;

    /// Return the OCI state of a container.
    async fn state(&self, request: StateRequest) -> Result<ContainerRecord>;

    /// Perform the OCI start operation.
    async fn start(&self, request: StartRequest) -> Result<ContainerRecord>;

    /// Deliver an OCI kill signal.
    async fn kill(&self, request: KillRequest) -> Result<ContainerRecord>;

    /// Delete runtime-owned container resources.
    async fn delete(&self, request: DeleteRequest) -> Result<()>;

    /// Execute an additional OCI process.
    async fn exec(&self, _request: ExecRequest) -> Result<ProcessRecord> {
        Err(Error::unsupported("exec"))
    }

    /// Wait for the container init process.
    async fn wait(&self, _request: WaitRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("wait"))
    }

    /// List containers visible in this runtime scope.
    async fn list(&self, _request: ListRequest) -> Result<Vec<ContainerRecord>> {
        Err(Error::unsupported("list"))
    }

    /// Pause all container processes.
    async fn pause(&self, _request: ContainerOperationRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("pause"))
    }

    /// Resume all container processes.
    async fn resume(&self, _request: ContainerOperationRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("resume"))
    }

    /// Apply OCI Linux resource changes.
    async fn update(&self, _request: UpdateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("update"))
    }

    /// List init and exec processes.
    async fn processes(&self, _request: ProcessesRequest) -> Result<Vec<ProcessRecord>> {
        Err(Error::unsupported("processes"))
    }

    /// Read a normalized resource snapshot.
    async fn stats(&self, _request: StatsRequest) -> Result<ContainerStats> {
        Err(Error::unsupported("stats"))
    }

    /// Poll ordered, cursor-based runtime events.
    async fn events(&self, _request: EventsRequest) -> Result<EventBatch> {
        Err(Error::unsupported("events"))
    }

    /// Poll ordered captured stdout and stderr frames.
    async fn read_output(&self, _request: ReadOutputRequest) -> Result<Vec<OutputChunk>> {
        Err(Error::unsupported("read-output"))
    }

    /// Write bytes to process stdin with backpressure.
    async fn write_stdin(&self, _request: WriteStdinRequest) -> Result<()> {
        Err(Error::unsupported("write-stdin"))
    }

    /// Close process stdin.
    async fn close_stdin(&self, _request: CloseStdinRequest) -> Result<()> {
        Err(Error::unsupported("close-stdin"))
    }

    /// Resize a process terminal.
    async fn resize(&self, _request: ResizeRequest) -> Result<()> {
        Err(Error::unsupported("resize"))
    }

    /// Signal one init or exec process.
    async fn signal_process(&self, _request: SignalProcessRequest) -> Result<()> {
        Err(Error::unsupported("signal-process"))
    }

    /// Wait for one init or exec process.
    async fn wait_process(&self, _request: WaitProcessRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("wait-process"))
    }

    /// Checkpoint a container.
    async fn checkpoint(&self, _request: CheckpointRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("checkpoint"))
    }

    /// Restore a container.
    async fn restore(&self, _request: RestoreRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("restore"))
    }
}
