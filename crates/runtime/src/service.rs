use std::collections::HashMap;

use a3s_oci_sdk::oci_spec::runtime::FeaturesBuilder;
use a3s_oci_sdk::{
    async_trait, CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, CreateRequest, DeleteRequest, Error, ErrorCode, EventBatch, EventsRequest,
    ExecRequest, ExitStatus, KillRequest, ListRequest, OciRuntimeService, OutputChunk,
    ProcessRecord, ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest, Result,
    RuntimeInfo, RuntimeOperation, SignalProcessRequest, StartRequest, StateRequest, StatsRequest,
    UpdateRequest, WaitProcessRequest, WaitRequest, WriteStdinRequest,
    OCI_RUNTIME_SPEC_VERSION_MAX, OCI_RUNTIME_SPEC_VERSION_MIN,
};

/// In-process host implementation used by the CLI and A3S Box adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostRuntimeService;

impl HostRuntimeService {
    /// Construct the local host service.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
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
                "probe-only".to_string(),
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

        Ok(RuntimeInfo {
            oci,
            drivers: crate::features(),
            operations: vec![RuntimeOperation::Features],
        })
    }

    async fn create(&self, _request: CreateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("create"))
    }

    async fn state(&self, _request: StateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("state"))
    }

    async fn start(&self, _request: StartRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("start"))
    }

    async fn kill(&self, _request: KillRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("kill"))
    }

    async fn delete(&self, _request: DeleteRequest) -> Result<()> {
        Err(Error::unsupported("delete"))
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
mod tests {
    use a3s_oci_sdk::{ErrorCode, OciRuntimeService, RuntimeOperation};

    use super::HostRuntimeService;

    #[tokio::test]
    async fn reports_only_operations_that_are_currently_implemented() {
        let info = HostRuntimeService::new()
            .features()
            .await
            .expect("feature discovery must succeed");

        assert_eq!(info.operations, vec![RuntimeOperation::Features]);
        assert_eq!(info.oci.oci_version_min(), "1.0.0");
        assert_eq!(info.oci.oci_version_max(), "1.3.0");
    }

    #[tokio::test]
    async fn incomplete_lifecycle_fails_explicitly() {
        let error = HostRuntimeService::new()
            .list(Default::default())
            .await
            .expect_err("list must remain disabled before durable state exists");

        assert_eq!(error.code, ErrorCode::Unsupported);
        assert_eq!(error.operation.as_deref(), Some("list"));
    }
}
