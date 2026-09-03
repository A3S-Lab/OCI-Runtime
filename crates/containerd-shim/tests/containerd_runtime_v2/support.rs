use std::io;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use super::api::{
    self, ContainersClient, GetContainerRequest, GetTaskRequest, Mount, MountsRequest, Process,
    SnapshotsClient, TasksClient, VersionClient, VersionRequest,
};
use serde_json::Value;
use tokio::process::Command;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::Channel;
use tonic::{Code, Request};

use super::restart_boundaries::RestartBoundaryLedger;

pub(crate) type TestError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type TestResult<T> = Result<T, TestError>;

pub(crate) const STATUS_CREATED: i32 = 1;
pub(crate) const STATUS_RUNNING: i32 = 2;
pub(crate) const STATUS_STOPPED: i32 = 3;
pub(crate) const STATUS_PAUSED: i32 = 4;
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(crate) struct QualificationConfig {
    pub(crate) socket: PathBuf,
    pub(crate) ttrpc_address: String,
    pub(crate) runtime_endpoint: PathBuf,
    state_root: PathBuf,
    pub(crate) namespace: String,
    pub(crate) image: String,
    pub(crate) runtime: String,
    service: String,
    pub(crate) restart_boundaries: RestartBoundaryLedger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeIdentity {
    pub(crate) container_id: a3s_oci_sdk::ContainerId,
    pub(crate) incarnation: String,
    pub(crate) generation: u64,
}

impl QualificationConfig {
    pub(crate) fn from_environment() -> TestResult<Self> {
        require_environment("A3S_OCI_CONTAINERD_QUALIFY", "1")?;
        require_environment("A3S_OCI_CONTAINERD_ALLOW_RESTART", "1")?;
        let runtime_endpoint = std::env::var("A3S_OCI_RUNTIME_ENDPOINT")
            .or_else(|_| std::env::var("A3S_OCI_RUNTIME_SOCKET"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/run/a3s-oci/runtime.sock"));
        Ok(Self {
            socket: environment_path(
                "A3S_OCI_CONTAINERD_SOCKET",
                "/run/containerd/containerd.sock",
            ),
            ttrpc_address: environment_value(
                "A3S_OCI_CONTAINERD_TTRPC_ADDRESS",
                "/run/containerd/containerd.sock.ttrpc",
            ),
            runtime_endpoint,
            state_root: environment_path(
                "A3S_OCI_CONTAINERD_STATE_ROOT",
                "/run/containerd/io.containerd.runtime.v2.task",
            ),
            namespace: environment_value("A3S_OCI_CONTAINERD_NAMESPACE", "default"),
            image: environment_value(
                "A3S_OCI_CONTAINERD_IMAGE",
                "docker.io/library/busybox:latest",
            ),
            runtime: environment_value("A3S_OCI_CONTAINERD_RUNTIME", "io.containerd.a3s-oci.v2"),
            service: environment_value("A3S_OCI_CONTAINERD_SERVICE", "containerd"),
            restart_boundaries: RestartBoundaryLedger::default(),
        })
    }

    pub(crate) fn bundle(&self, id: &str) -> PathBuf {
        self.state_root.join(&self.namespace).join(id)
    }
}

pub(crate) async fn create_container(config: &QualificationConfig, id: &str) -> TestResult<()> {
    let output = ctr_output(
        config,
        &[
            "containers",
            "create",
            "--runtime",
            &config.runtime,
            &config.image,
            id,
            "/bin/sh",
            "-c",
            "trap 'exit 42' TERM; while :; do sleep 1; done",
        ],
    )
    .await?;
    require_success("create container metadata", &output)
}

pub(crate) async fn delete_container(config: &QualificationConfig, id: &str) -> TestResult<()> {
    let output = ctr_output(config, &["containers", "delete", id]).await?;
    require_success("delete container metadata", &output)
}

pub(crate) async fn task_rootfs(
    config: &QualificationConfig,
    channel: &Channel,
    id: &str,
) -> TestResult<Vec<Mount>> {
    let container = ContainersClient::new(channel.clone())
        .get(namespaced(
            GetContainerRequest { id: id.to_string() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("read container metadata", error))?
        .into_inner()
        .container
        .ok_or_else(|| qualification_error("containerd omitted container metadata"))?;
    if container.snapshot_key.is_empty() {
        return Ok(Vec::new());
    }
    let mounts = SnapshotsClient::new(channel.clone())
        .mounts(namespaced(
            MountsRequest {
                snapshotter: container.snapshotter,
                key: container.snapshot_key,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("resolve container snapshot mounts", error))?
        .into_inner()
        .mounts;
    if mounts.is_empty() {
        return Err(qualification_error("container snapshot returned no rootfs mounts").into());
    }
    Ok(mounts)
}

pub(crate) async fn task_process(
    config: &QualificationConfig,
    channel: &Channel,
    id: &str,
    exec_id: &str,
) -> TestResult<Process> {
    optional_task_process(config, channel, id, exec_id)
        .await?
        .ok_or_else(|| qualification_error("containerd omitted task process state").into())
}

pub(crate) async fn optional_task_process(
    config: &QualificationConfig,
    channel: &Channel,
    id: &str,
    exec_id: &str,
) -> TestResult<Option<Process>> {
    let result = TasksClient::new(channel.clone())
        .get(namespaced(
            GetTaskRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await;
    match result {
        Ok(response) => response
            .into_inner()
            .process
            .map(Some)
            .ok_or_else(|| qualification_error("containerd omitted task process state").into()),
        Err(error) if error.code() == Code::NotFound => Ok(None),
        Err(error) => Err(rpc_error("read task state", error).into()),
    }
}

pub(crate) async fn wait_for_bundle_removal(
    config: &QualificationConfig,
    id: &str,
) -> TestResult<()> {
    let bundle = config.bundle(id);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::fs::try_exists(&bundle).await {
            Ok(false) => return Ok(()),
            Ok(true) if tokio::time::Instant::now() < deadline => {}
            Ok(true) => {
                return Err(qualification_error(format!(
                    "containerd stopped-task recovery left shim bundle {}",
                    bundle.display()
                ))
                .into());
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "inspect stopped-task shim bundle {}: {error}",
                    bundle.display()
                ))
                .into());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(crate) fn expect_process(
    process: &Process,
    status: i32,
    pid: Option<u32>,
    context: &str,
) -> TestResult<()> {
    if process.status != status {
        return Err(qualification_error(format!(
            "{context} status was {}, expected {status}",
            process.status
        ))
        .into());
    }
    if let Some(pid) = pid {
        if process.pid != pid {
            return Err(qualification_error(format!(
                "{context} PID was {}, expected {pid}",
                process.pid
            ))
            .into());
        }
    }
    Ok(())
}

pub(crate) async fn read_runtime_identity(
    config: &QualificationConfig,
    id: &str,
) -> TestResult<RuntimeIdentity> {
    let bundle = config.bundle(id);
    let incarnation = tokio::fs::read_to_string(bundle.join("a3s-oci-shim-incarnation-v1"))
        .await
        .map_err(|error| {
            qualification_error(format!("read containerd task incarnation: {error}"))
        })?;
    let metadata = tokio::fs::read(bundle.join("a3s-oci-shim-v1.json"))
        .await
        .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?;
    let metadata: Value = serde_json::from_slice(&metadata)
        .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
    let generation = metadata
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| qualification_error("shim metadata omitted a numeric generation"))?;
    let container_id = metadata
        .get("container_id")
        .and_then(Value::as_str)
        .ok_or_else(|| qualification_error("shim metadata omitted its runtime container ID"))?;
    Ok(RuntimeIdentity {
        container_id: a3s_oci_sdk::ContainerId::new(container_id).map_err(|error| {
            qualification_error(format!(
                "shim metadata contains an invalid runtime container ID: {error}"
            ))
        })?,
        incarnation,
        generation,
    })
}

pub(crate) async fn restart_containerd(
    config: &QualificationConfig,
    boundary: &str,
) -> TestResult<Channel> {
    let reset = command_output("systemctl", &["reset-failed", &config.service]).await?;
    require_success(
        &format!("reset containerd start limit before {boundary} restart"),
        &reset,
    )?;
    eprintln!("restarting containerd at {boundary}");
    let output = command_output("systemctl", &["restart", &config.service]).await?;
    require_success(&format!("restart containerd at {boundary}"), &output)?;
    let channel = connect_ready(config).await?;
    config
        .restart_boundaries
        .record(boundary)
        .map_err(|error| {
            qualification_error(format!(
                "record successful containerd restart at {boundary}: {error}"
            ))
        })?;
    Ok(channel)
}

pub(crate) async fn containerd_main_pid(config: &QualificationConfig) -> TestResult<u32> {
    let output = command_output(
        "systemctl",
        &["show", "--property", "MainPID", "--value", &config.service],
    )
    .await?;
    require_success("read containerd MainPID", &output)?;
    let pid = String::from_utf8(output.stdout)
        .map_err(|error| qualification_error(format!("decode containerd MainPID: {error}")))?
        .trim()
        .parse::<u32>()
        .map_err(|error| qualification_error(format!("parse containerd MainPID: {error}")))?;
    if pid <= 1 {
        return Err(qualification_error(format!(
            "containerd MainPID was {pid}; refusing to signal a non-service PID"
        ))
        .into());
    }
    Ok(pid)
}

pub(crate) async fn connect_ready(config: &QualificationConfig) -> TestResult<Channel> {
    let deadline = tokio::time::Instant::now() + RECONNECT_TIMEOUT;
    loop {
        let attempt_error = match api::connect(&config.socket).await {
            Ok(channel) => {
                let result = VersionClient::new(channel.clone())
                    .version(Request::new(VersionRequest {}))
                    .await;
                match result {
                    Ok(_) => return Ok(channel),
                    Err(error) => error.to_string(),
                }
            }
            Err(error) => error.to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "containerd did not become ready at {} within {} seconds: {attempt_error}",
                config.socket.display(),
                RECONNECT_TIMEOUT.as_secs()
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(crate) async fn cleanup_exact(config: &QualificationConfig, prefix: &str) -> TestResult<()> {
    let reset = command_output("systemctl", &["reset-failed", &config.service]).await?;
    require_success("reset containerd start limit for cleanup", &reset)?;
    let start = command_output("systemctl", &["start", &config.service]).await?;
    require_success("restore containerd for cleanup", &start)?;
    connect_ready(config).await?;
    let tasks = ctr_output(config, &["tasks", "list", "--quiet"]).await?;
    require_success("list tasks for cleanup", &tasks)?;
    let containers = ctr_output(config, &["containers", "list", "--quiet"]).await?;
    require_success("list containers for cleanup", &containers)?;
    let mut ids = String::from_utf8_lossy(&tasks.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&containers.stdout).lines())
        .filter(|id| id.starts_with(prefix))
        .map(str::to_string)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    for id in &ids {
        let _ = ctr_output(config, &["tasks", "delete", "--force", id]).await;
    }
    for id in &ids {
        let _ = ctr_output(config, &["containers", "delete", id]).await;
    }
    let tasks = ctr_output(config, &["tasks", "list", "--quiet"]).await?;
    let containers = ctr_output(config, &["containers", "list", "--quiet"]).await?;
    let task_ids = String::from_utf8_lossy(&tasks.stdout);
    let container_ids = String::from_utf8_lossy(&containers.stdout);
    let residue = task_ids
        .lines()
        .chain(container_ids.lines())
        .filter(|id| id.starts_with(prefix))
        .collect::<Vec<_>>();
    if !residue.is_empty() {
        return Err(qualification_error(format!(
            "containerd qualification left task/container residue: {residue:?}"
        ))
        .into());
    }
    Ok(())
}

pub(crate) fn namespaced<T>(value: T, namespace: &str) -> TestResult<Request<T>> {
    let metadata: MetadataValue<Ascii> = MetadataValue::try_from(namespace).map_err(|error| {
        qualification_error(format!("invalid containerd namespace metadata: {error}"))
    })?;
    let mut request = Request::new(value);
    request
        .metadata_mut()
        .insert("containerd-namespace", metadata);
    Ok(request)
}

pub(crate) fn ctr_command(config: &QualificationConfig) -> Command {
    let mut command = Command::new("ctr");
    command.args(["--namespace", &config.namespace]);
    command
}

async fn ctr_output(config: &QualificationConfig, arguments: &[&str]) -> TestResult<Output> {
    let mut command = ctr_command(config);
    command.args(arguments);
    output_with_timeout(command, "ctr").await
}

async fn command_output(program: &str, arguments: &[&str]) -> TestResult<Output> {
    let mut command = Command::new(program);
    command.args(arguments);
    output_with_timeout(command, program).await
}

async fn output_with_timeout(mut command: Command, context: &str) -> TestResult<Output> {
    tokio::time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| qualification_error(format!("{context} exceeded 60 seconds")))?
        .map_err(|error| qualification_error(format!("run {context}: {error}")).into())
}

pub(crate) fn require_success(context: &str, output: &Output) -> TestResult<()> {
    if output.status.success() {
        return Ok(());
    }
    Err(qualification_error(format!(
        "{context} failed with {}: stdout={:?}, stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
    .into())
}

pub(crate) async fn require_root() -> TestResult<()> {
    let output = command_output("id", &["-u"]).await?;
    require_success("inspect effective UID", &output)?;
    if String::from_utf8_lossy(&output.stdout).trim() != "0" {
        return Err(qualification_error(
            "real containerd qualification must run as root to access the containerd socket and restart the service",
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn require_command(command: &str) -> TestResult<()> {
    let output = command_output("sh", &["-c", &format!("command -v {command}")]).await?;
    require_success(&format!("locate {command}"), &output)
}

fn require_environment(name: &str, expected: &str) -> TestResult<()> {
    let actual = std::env::var(name).unwrap_or_default();
    if actual != expected {
        return Err(qualification_error(format!(
            "set {name}={expected} to acknowledge the destructive real-containerd qualification boundary"
        ))
        .into());
    }
    Ok(())
}

fn environment_value(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn environment_path(name: &str, default: &str) -> PathBuf {
    Path::new(&environment_value(name, default)).to_path_buf()
}

pub(crate) fn rpc_error(operation: &str, error: impl std::fmt::Display) -> io::Error {
    qualification_error(format!("containerd {operation} RPC failed: {error}"))
}

pub(crate) fn qualification_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
