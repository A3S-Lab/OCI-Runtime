use std::io;
use std::path::Path;

use http::uri::PathAndQuery;
use hyper_util::rt::TokioIo;
use prost::Message;
use prost_types::{Any, Timestamp};
use tonic::client::Grpc;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Empty {}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Mount {
    #[prost(string, tag = "1")]
    pub(crate) r#type: String,
    #[prost(string, tag = "2")]
    pub(crate) source: String,
    #[prost(string, tag = "3")]
    pub(crate) target: String,
    #[prost(string, repeated, tag = "4")]
    pub(crate) options: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Container {
    #[prost(string, tag = "6")]
    pub(crate) snapshotter: String,
    #[prost(string, tag = "7")]
    pub(crate) snapshot_key: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GetContainerRequest {
    #[prost(string, tag = "1")]
    pub(crate) id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GetContainerResponse {
    #[prost(message, optional, tag = "1")]
    pub(crate) container: Option<Container>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MountsRequest {
    #[prost(string, tag = "1")]
    pub(crate) snapshotter: String,
    #[prost(string, tag = "2")]
    pub(crate) key: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MountsResponse {
    #[prost(message, repeated, tag = "1")]
    pub(crate) mounts: Vec<Mount>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Process {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) id: String,
    #[prost(uint32, tag = "3")]
    pub(crate) pid: u32,
    #[prost(int32, tag = "4")]
    pub(crate) status: i32,
    #[prost(string, tag = "5")]
    pub(crate) stdin: String,
    #[prost(string, tag = "6")]
    pub(crate) stdout: String,
    #[prost(string, tag = "7")]
    pub(crate) stderr: String,
    #[prost(bool, tag = "8")]
    pub(crate) terminal: bool,
    #[prost(uint32, tag = "9")]
    pub(crate) exit_status: u32,
    #[prost(message, optional, tag = "10")]
    pub(crate) exited_at: Option<Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProcessInfo {
    #[prost(uint32, tag = "1")]
    pub(crate) pid: u32,
    #[prost(message, optional, tag = "2")]
    pub(crate) info: Option<Any>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Metric {
    #[prost(message, optional, tag = "1")]
    pub(crate) timestamp: Option<Timestamp>,
    #[prost(string, tag = "2")]
    pub(crate) id: String,
    #[prost(message, optional, tag = "3")]
    pub(crate) data: Option<Any>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct CreateTaskRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(message, repeated, tag = "3")]
    pub(crate) rootfs: Vec<Mount>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct CreateTaskResponse {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(uint32, tag = "2")]
    pub(crate) pid: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct StartRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct StartResponse {
    #[prost(uint32, tag = "1")]
    pub(crate) pid: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DeleteTaskRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DeleteProcessRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DeleteResponse {
    #[prost(string, tag = "1")]
    pub(crate) id: String,
    #[prost(uint32, tag = "2")]
    pub(crate) pid: u32,
    #[prost(uint32, tag = "3")]
    pub(crate) exit_status: u32,
    #[prost(message, optional, tag = "4")]
    pub(crate) exited_at: Option<Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GetTaskRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GetTaskResponse {
    #[prost(message, optional, tag = "1")]
    pub(crate) process: Option<Process>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct KillRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) exec_id: String,
    #[prost(uint32, tag = "3")]
    pub(crate) signal: u32,
    #[prost(bool, tag = "4")]
    pub(crate) all: bool,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ExecProcessRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) stdin: String,
    #[prost(string, tag = "3")]
    pub(crate) stdout: String,
    #[prost(string, tag = "4")]
    pub(crate) stderr: String,
    #[prost(bool, tag = "5")]
    pub(crate) terminal: bool,
    #[prost(message, optional, tag = "6")]
    pub(crate) spec: Option<Any>,
    #[prost(string, tag = "7")]
    pub(crate) exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct CloseIORequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) exec_id: String,
    #[prost(bool, tag = "3")]
    pub(crate) stdin: bool,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ResizePtyRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) exec_id: String,
    #[prost(uint32, tag = "3")]
    pub(crate) width: u32,
    #[prost(uint32, tag = "4")]
    pub(crate) height: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct PauseTaskRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ResumeTaskRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ListPidsRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ListPidsResponse {
    #[prost(message, repeated, tag = "1")]
    pub(crate) processes: Vec<ProcessInfo>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct UpdateTaskRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(message, optional, tag = "2")]
    pub(crate) resources: Option<Any>,
    #[prost(map = "string, string", tag = "3")]
    pub(crate) annotations: std::collections::HashMap<String, String>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MetricsRequest {
    #[prost(string, repeated, tag = "1")]
    pub(crate) filters: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MetricsResponse {
    #[prost(message, repeated, tag = "1")]
    pub(crate) metrics: Vec<Metric>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct WaitRequest {
    #[prost(string, tag = "1")]
    pub(crate) container_id: String,
    #[prost(string, tag = "2")]
    pub(crate) exec_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct WaitResponse {
    #[prost(uint32, tag = "1")]
    pub(crate) exit_status: u32,
    #[prost(message, optional, tag = "2")]
    pub(crate) exited_at: Option<Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct VersionRequest {}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct VersionResponse {
    #[prost(string, tag = "1")]
    pub(crate) version: String,
    #[prost(string, tag = "2")]
    pub(crate) revision: String,
}

pub(crate) async fn connect(path: impl AsRef<Path>) -> Result<Channel, tonic::transport::Error> {
    let path = path.as_ref().to_path_buf();
    Endpoint::try_from("http://[::]")?
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                Ok::<_, io::Error>(TokioIo::new(tokio::net::UnixStream::connect(path).await?))
            }
        }))
        .await
}

async fn unary<Q, P>(
    channel: Channel,
    request: Request<Q>,
    path: &'static str,
) -> Result<Response<P>, Status>
where
    Q: Message + Send + 'static,
    P: Message + Default + Send + 'static,
{
    let mut client = Grpc::new(channel);
    client.ready().await.map_err(|error| {
        Status::unknown(format!("containerd gRPC service is not ready: {error}"))
    })?;
    client
        .unary(
            request,
            PathAndQuery::from_static(path),
            tonic_prost::ProstCodec::default(),
        )
        .await
}

macro_rules! unary_method {
    ($name:ident, $request:ty, $response:ty, $path:literal) => {
        pub(crate) async fn $name(
            &mut self,
            request: Request<$request>,
        ) -> Result<Response<$response>, Status> {
            unary(self.channel.clone(), request, $path).await
        }
    };
}

#[derive(Clone)]
pub(crate) struct ContainersClient {
    channel: Channel,
}

impl ContainersClient {
    pub(crate) const fn new(channel: Channel) -> Self {
        Self { channel }
    }

    unary_method!(
        get,
        GetContainerRequest,
        GetContainerResponse,
        "/containerd.services.containers.v1.Containers/Get"
    );
}

#[derive(Clone)]
pub(crate) struct SnapshotsClient {
    channel: Channel,
}

impl SnapshotsClient {
    pub(crate) const fn new(channel: Channel) -> Self {
        Self { channel }
    }

    unary_method!(
        mounts,
        MountsRequest,
        MountsResponse,
        "/containerd.services.snapshots.v1.Snapshots/Mounts"
    );
}

#[derive(Clone)]
pub(crate) struct TasksClient {
    channel: Channel,
}

impl TasksClient {
    pub(crate) const fn new(channel: Channel) -> Self {
        Self { channel }
    }

    unary_method!(
        create,
        CreateTaskRequest,
        CreateTaskResponse,
        "/containerd.services.tasks.v1.Tasks/Create"
    );
    unary_method!(
        start,
        StartRequest,
        StartResponse,
        "/containerd.services.tasks.v1.Tasks/Start"
    );
    unary_method!(
        delete,
        DeleteTaskRequest,
        DeleteResponse,
        "/containerd.services.tasks.v1.Tasks/Delete"
    );
    unary_method!(
        delete_process,
        DeleteProcessRequest,
        DeleteResponse,
        "/containerd.services.tasks.v1.Tasks/DeleteProcess"
    );
    unary_method!(
        get,
        GetTaskRequest,
        GetTaskResponse,
        "/containerd.services.tasks.v1.Tasks/Get"
    );
    unary_method!(
        kill,
        KillRequest,
        Empty,
        "/containerd.services.tasks.v1.Tasks/Kill"
    );
    unary_method!(
        exec,
        ExecProcessRequest,
        Empty,
        "/containerd.services.tasks.v1.Tasks/Exec"
    );
    unary_method!(
        close_io,
        CloseIORequest,
        Empty,
        "/containerd.services.tasks.v1.Tasks/CloseIO"
    );
    unary_method!(
        resize_pty,
        ResizePtyRequest,
        Empty,
        "/containerd.services.tasks.v1.Tasks/ResizePty"
    );
    unary_method!(
        pause,
        PauseTaskRequest,
        Empty,
        "/containerd.services.tasks.v1.Tasks/Pause"
    );
    unary_method!(
        resume,
        ResumeTaskRequest,
        Empty,
        "/containerd.services.tasks.v1.Tasks/Resume"
    );
    unary_method!(
        list_pids,
        ListPidsRequest,
        ListPidsResponse,
        "/containerd.services.tasks.v1.Tasks/ListPids"
    );
    unary_method!(
        update,
        UpdateTaskRequest,
        Empty,
        "/containerd.services.tasks.v1.Tasks/Update"
    );
    unary_method!(
        metrics,
        MetricsRequest,
        MetricsResponse,
        "/containerd.services.tasks.v1.Tasks/Metrics"
    );
    unary_method!(
        wait,
        WaitRequest,
        WaitResponse,
        "/containerd.services.tasks.v1.Tasks/Wait"
    );
}

#[derive(Clone)]
pub(crate) struct VersionClient {
    channel: Channel,
}

impl VersionClient {
    pub(crate) const fn new(channel: Channel) -> Self {
        Self { channel }
    }

    unary_method!(
        version,
        VersionRequest,
        VersionResponse,
        "/containerd.services.version.v1.Version/Version"
    );
}
