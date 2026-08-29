use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
use a3s_oci_sdk::{
    serve_transport_connection, ContainerId, ContainerRecord, ContainerTarget, CreateRequest,
    DeleteMode, DeleteRequest, DriverKind, Error, ErrorCode, Generation, IsolationClass,
    KillRequest, OciRuntimeService, Result, RuntimeInfo, StartRequest, StateRequest,
};
use async_trait::async_trait;
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

#[derive(Default)]
pub(super) struct LifecycleService {
    inner: Mutex<LifecycleState>,
}

#[derive(Default)]
struct LifecycleState {
    generation: u64,
    record: Option<ContainerRecord>,
    create_operations: Vec<String>,
    start_operations: Vec<String>,
    kill_operations: Vec<(String, i32, bool)>,
    delete_operations: Vec<(String, DeleteMode)>,
}

impl LifecycleService {
    fn inner(&self) -> MutexGuard<'_, LifecycleState> {
        self.inner.lock().expect("lifecycle service lock")
    }

    pub(super) fn assert_complete_lifecycle(&self) {
        let inner = self.inner();
        assert_eq!(inner.generation, 2);
        assert_eq!(inner.create_operations.len(), 2);
        assert_ne!(inner.create_operations[0], inner.create_operations[1]);
        assert_eq!(inner.start_operations.len(), 1);
        assert_eq!(inner.kill_operations.len(), 1);
        assert_eq!(inner.kill_operations[0].1, 15);
        assert!(inner.kill_operations[0].2);
        assert_eq!(
            inner
                .delete_operations
                .iter()
                .map(|(_, mode)| *mode)
                .collect::<Vec<_>>(),
            [DeleteMode::StoppedOnly, DeleteMode::Force]
        );
    }
}

#[async_trait]
impl OciRuntimeService for LifecycleService {
    async fn features(&self) -> Result<RuntimeInfo> {
        Err(Error::unsupported("features"))
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        let mut inner = self.inner();
        if inner.record.is_some() {
            return Err(
                Error::new(ErrorCode::AlreadyExists, "test container already exists")
                    .for_operation("create"),
            );
        }
        inner.generation += 1;
        inner
            .create_operations
            .push(request.context.operation_id.to_string());
        let generation = Generation(inner.generation);
        let pid = 4_200
            + i32::try_from(inner.generation)
                .map_err(|error| service_error("create", error.to_string()))?;
        let record = build_record(
            &request.id,
            generation,
            ContainerState::Created,
            Some(pid),
            request.bundle.directory(),
            request.bundle.config_digest(),
            &request.attachments.digest()?,
            request.isolation.class(),
        )?;
        inner.record = Some(record.clone());
        Ok(record)
    }

    async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        matching_record(&self.inner(), &request.target)
    }

    async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        let mut inner = self.inner();
        let current = matching_record(&inner, &request.target)?;
        if *current.state.status() != ContainerState::Created {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "test start requires a created container",
            )
            .for_operation("start"));
        }
        inner
            .start_operations
            .push(request.context.operation_id.to_string());
        let running = transition(&current, ContainerState::Running, *current.state.pid())?;
        inner.record = Some(running.clone());
        Ok(running)
    }

    async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        let mut inner = self.inner();
        let current = matching_record(&inner, &request.target)?;
        if !matches!(
            *current.state.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "test kill requires a created or running container",
            )
            .for_operation("kill"));
        }
        inner.kill_operations.push((
            request.context.operation_id.to_string(),
            request.signal.get(),
            request.all,
        ));
        let stopped = transition(&current, ContainerState::Stopped, None)?;
        inner.record = Some(stopped.clone());
        Ok(stopped)
    }

    async fn delete(&self, request: DeleteRequest) -> Result<()> {
        let mut inner = self.inner();
        let current = matching_record(&inner, &request.target)?;
        if request.mode == DeleteMode::StoppedOnly
            && *current.state.status() != ContainerState::Stopped
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "test stopped-only delete requires a stopped container",
            )
            .for_operation("delete"));
        }
        inner
            .delete_operations
            .push((request.context.operation_id.to_string(), request.mode));
        inner.record = None;
        Ok(())
    }
}

pub(super) struct TestServer {
    endpoint: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::result::Result<(), String>>>,
}

impl TestServer {
    pub(super) fn start(root: &Path, service: Arc<LifecycleService>) -> Self {
        let endpoint = test_endpoint(root);
        let (shutdown_send, shutdown_receive) = oneshot::channel();
        let task = spawn_server(&endpoint, service, shutdown_receive);
        Self {
            endpoint,
            shutdown: Some(shutdown_send),
            task: Some(task),
        }
    }

    pub(super) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(super) async fn finish(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .expect("lifecycle test server task must join")
                .expect("serve lifecycle test clients");
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(unix)]
fn test_endpoint(root: &Path) -> String {
    root.join("runtime.sock").to_string_lossy().into_owned()
}

#[cfg(windows)]
fn test_endpoint(_root: &Path) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    format!(
        r"\\.\pipe\a3s-oci-cli-lifecycle-{}-{nonce}",
        std::process::id()
    )
}

#[cfg(unix)]
fn spawn_server(
    endpoint: &str,
    service: Arc<LifecycleService>,
    shutdown: oneshot::Receiver<()>,
) -> JoinHandle<std::result::Result<(), String>> {
    let listener = tokio::net::UnixListener::bind(endpoint)
        .unwrap_or_else(|error| panic!("bind Unix lifecycle socket {endpoint}: {error}"));
    tokio::spawn(serve_endpoint(listener, service, shutdown))
}

#[cfg(windows)]
fn spawn_server(
    endpoint: &str,
    service: Arc<LifecycleService>,
    shutdown: oneshot::Receiver<()>,
) -> JoinHandle<std::result::Result<(), String>> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true);
    let pending = options
        .create(endpoint)
        .unwrap_or_else(|error| panic!("bind Windows lifecycle pipe {endpoint}: {error}"));
    tokio::spawn(serve_endpoint(
        endpoint.to_string(),
        pending,
        service,
        shutdown,
    ))
}

#[cfg(unix)]
async fn serve_endpoint(
    listener: tokio::net::UnixListener,
    service: Arc<LifecycleService>,
    mut shutdown: oneshot::Receiver<()>,
) -> std::result::Result<(), String> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|error| format!("accept lifecycle client: {error}"))?;
                let service: Arc<dyn OciRuntimeService> = service.clone();
                connections.spawn(serve_transport_connection(service, stream));
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                check_connection(completed)?;
            }
        }
    }
    finish_connections(&mut connections).await;
    Ok(())
}

#[cfg(windows)]
async fn serve_endpoint(
    endpoint: String,
    mut pending: tokio::net::windows::named_pipe::NamedPipeServer,
    service: Arc<LifecycleService>,
    mut shutdown: oneshot::Receiver<()>,
) -> std::result::Result<(), String> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = pending.connect() => {
                accepted.map_err(|error| format!("accept lifecycle client: {error}"))?;
                let replacement = ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&endpoint)
                    .map_err(|error| format!("publish replacement lifecycle pipe: {error}"))?;
                let stream = std::mem::replace(&mut pending, replacement);
                let service: Arc<dyn OciRuntimeService> = service.clone();
                connections.spawn(serve_transport_connection(service, stream));
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                check_connection(completed)?;
            }
        }
    }
    finish_connections(&mut connections).await;
    Ok(())
}

fn check_connection(
    completed: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
) -> std::result::Result<(), String> {
    match completed {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(error))) => Err(format!("serve lifecycle client: {error}")),
        Some(Err(error)) => Err(format!("lifecycle client task failed: {error}")),
    }
}

async fn finish_connections(connections: &mut JoinSet<Result<()>>) {
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

fn matching_record(inner: &LifecycleState, target: &ContainerTarget) -> Result<ContainerRecord> {
    let record = inner.record.as_ref().ok_or_else(container_not_found)?;
    if record.state.id() != target.id.as_str()
        || target
            .generation
            .is_some_and(|generation| generation != record.generation)
    {
        return Err(container_not_found());
    }
    Ok(record.clone())
}

fn transition(
    current: &ContainerRecord,
    status: ContainerState,
    pid: Option<i32>,
) -> Result<ContainerRecord> {
    build_record(
        &ContainerId::new(current.state.id().to_string())?,
        current.generation,
        status,
        pid,
        current.state.bundle(),
        &current.config_digest,
        current
            .attachments_digest
            .as_deref()
            .ok_or_else(|| service_error("transition", "missing attachment digest"))?,
        current.isolation,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    id: &ContainerId,
    generation: Generation,
    status: ContainerState,
    pid: Option<i32>,
    bundle: &Path,
    config_digest: &str,
    attachments_digest: &str,
    isolation: IsolationClass,
) -> Result<ContainerRecord> {
    let mut builder = StateBuilder::default()
        .version("1.3.0")
        .id(id.as_str())
        .status(status)
        .bundle(bundle.to_path_buf());
    if let Some(pid) = pid {
        builder = builder.pid(pid);
    }
    Ok(ContainerRecord {
        state: builder
            .build()
            .map_err(|error| service_error("build-state", error.to_string()))?,
        generation,
        driver: DriverKind::NativeLinux,
        isolation,
        guest_session: None,
        network_enforcement: None,
        config_digest: config_digest.to_string(),
        attachments_digest: Some(attachments_digest.to_string()),
    })
}

fn container_not_found() -> Error {
    Error::new(ErrorCode::NotFound, "test container not found").for_operation("state")
}

fn service_error(operation: &'static str, message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Internal, message).for_operation(operation)
}
