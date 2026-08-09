use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerStats, ContainerTarget, CpuStats, DeleteMode, Error,
    ErrorCode, ExitStatus, FileOp, FileRequest, FileResponse, FilesystemEntry, FilesystemEntryKind,
    FilesystemOp, FilesystemRequest, FilesystemResponse, Generation, IoMode, MemoryStats,
    OciBundle, OperationContext, OperationId, OutputChunk, OutputStream, ProcessId, ProcessIo,
    ProcessRecord, ProcessTarget, Result, Signal, TerminalSize,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use crate::model::{
    AgentCloseStdinRequest, AgentContainerOperationRequest, AgentCreateRequest, AgentDeleteRequest,
    AgentExecRequest, AgentHello, AgentKillRequest, AgentProcess, AgentProcessesRequest,
    AgentReadOutputRequest, AgentRequest, AgentResizeRequest, AgentResponse,
    AgentSignalProcessRequest, AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest,
    AgentUpdateRequest, AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest,
    HelloOutcome, HostHello, ProtocolRange, RequestEnvelope, ResponseEnvelope, ResponseOutcome,
};
use crate::wire::{read_frame, read_frame_for_test, write_frame};
use crate::{
    serve_agent_connection, AgentCapabilities, AgentClient, GuestAgentService, GuestPath,
    SessionToken,
};

mod process;
mod protocol;
mod response_replay;
mod transport_failures;

const TEST_CONFIG: &str = concat!(
    "{\n",
    "  \"ociVersion\": \"1.3.0\",\n",
    "  \"process\": {\n",
    "    \"terminal\": false,\n",
    "    \"user\": {\"uid\": 0, \"gid\": 0},\n",
    "    \"args\": [\"/bin/true\"],\n",
    "    \"cwd\": \"/\"\n",
    "  },\n",
    "  \"root\": {\"path\": \"rootfs\", \"readonly\": true}\n",
    "}\n",
);

#[derive(Debug, Default)]
struct TestAgent {
    state: Mutex<TestAgentState>,
    wait_dispatches: AtomicUsize,
    exec_dispatches: AtomicUsize,
}

#[derive(Debug, Default)]
struct TestAgentState {
    states: HashMap<ContainerId, AgentState>,
    highest_generations: HashMap<ContainerId, Generation>,
    exits: HashMap<ContainerId, ExitStatus>,
    processes: HashMap<(ContainerId, Generation, ProcessId), AgentProcess>,
    process_exits: HashMap<(ContainerId, Generation, ProcessId), ExitStatus>,
    stdin: HashMap<(ContainerId, Generation, ProcessId), Vec<u8>>,
    stdin_closed: HashSet<(ContainerId, Generation, ProcessId)>,
    terminal_sizes: HashMap<(ContainerId, Generation, ProcessId), TerminalSize>,
    next_pid: i32,
}

#[async_trait]
impl GuestAgentService for TestAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "0.1.0-test",
            std::env::consts::ARCH,
            vec![
                crate::AgentOperation::Create,
                crate::AgentOperation::State,
                crate::AgentOperation::Start,
                crate::AgentOperation::Kill,
                crate::AgentOperation::Delete,
                crate::AgentOperation::Wait,
                crate::AgentOperation::Exec,
                crate::AgentOperation::SignalProcess,
                crate::AgentOperation::WaitProcess,
                crate::AgentOperation::Pause,
                crate::AgentOperation::Resume,
                crate::AgentOperation::Processes,
                crate::AgentOperation::Update,
                crate::AgentOperation::Stats,
                crate::AgentOperation::ReadOutput,
                crate::AgentOperation::WriteStdin,
                crate::AgentOperation::CloseStdin,
                crate::AgentOperation::Resize,
                crate::AgentOperation::File,
                crate::AgentOperation::Filesystem,
            ],
        )
        .expect("valid test capabilities")
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        let generation = request
            .target
            .generation
            .expect("validated guest create carries an exact generation");
        let mut agent = self.state.lock().expect("agent state lock");
        if agent.states.contains_key(&request.target.id) {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                "guest container ID is already active",
            ));
        }
        if agent
            .highest_generations
            .get(&request.target.id)
            .is_some_and(|highest| generation <= *highest)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation is stale",
            ));
        }
        agent.next_pid += 101;
        let state = AgentState::new(
            request.target.clone(),
            ContainerState::Created,
            Some(agent.next_pid),
            request.bundle.config_digest(),
        )?;
        agent
            .highest_generations
            .insert(request.target.id.clone(), generation);
        agent.states.insert(request.target.id, state.clone());
        Ok(state)
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        let state = self
            .state
            .lock()
            .expect("agent state lock")
            .states
            .get(&request.target.id)
            .cloned()
            .ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "guest container does not exist")
                    .for_operation("agent-state")
            })?;
        if state.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        Ok(state)
    }

    async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
        let mut agent = self.state.lock().expect("agent state lock");
        let current = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        if current.status() != ContainerState::Created
            || current.config_digest() != request.expected_config_digest
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest container cannot start from its current state",
            ));
        }
        let state = AgentState::new(
            request.target.clone(),
            ContainerState::Running,
            current.pid(),
            request.expected_config_digest,
        )?;
        agent.states.insert(request.target.id, state.clone());
        Ok(state)
    }

    async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
        let mut agent = self.state.lock().expect("agent state lock");
        let current = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        let digest = current.config_digest().to_string();
        let state = AgentState::new(
            request.target.clone(),
            ContainerState::Stopped,
            None,
            digest,
        )?;
        agent.exits.insert(
            request.target.id.clone(),
            ExitStatus::signaled(request.signal.get(), false)?,
        );
        agent.states.insert(request.target.id, state.clone());
        Ok(state)
    }

    async fn wait(&self, request: AgentWaitRequest) -> Result<ExitStatus> {
        self.wait_dispatches.fetch_add(1, Ordering::SeqCst);
        let agent = self.state.lock().expect("agent state lock");
        let current = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        agent.exits.get(&request.target.id).cloned().ok_or_else(|| {
            Error::new(ErrorCode::DeadlineExceeded, "test container has not exited")
                .for_operation("agent-wait")
        })
    }

    async fn exec(&self, request: AgentExecRequest) -> Result<AgentProcess> {
        self.exec_dispatches.fetch_add(1, Ordering::SeqCst);
        let generation = request
            .target
            .container
            .generation
            .expect("validated guest exec carries an exact generation");
        let mut agent = self.state.lock().expect("agent state lock");
        let container = agent
            .states
            .get(&request.target.container.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if container.target() != &request.target.container {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        if container.status() != ContainerState::Running {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest exec requires a running container",
            ));
        }
        if container.paused() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest exec is unavailable while the container is paused",
            ));
        }
        let key = (
            request.target.container.id.clone(),
            generation,
            request.target.process_id.clone(),
        );
        if agent.processes.contains_key(&key) {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                "guest exec process ID already exists",
            ));
        }
        agent.next_pid += 101;
        let process = AgentProcess::new(
            request.target,
            agent.next_pid,
            request.process.terminal().unwrap_or(false),
        )?;
        agent.processes.insert(key, process.clone());
        Ok(process)
    }

    async fn signal_process(&self, request: AgentSignalProcessRequest) -> Result<()> {
        let key = process_key(&request.target)?;
        let mut agent = self.state.lock().expect("agent state lock");
        if !agent.processes.contains_key(&key) {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest exec process does not exist",
            ));
        }
        agent
            .process_exits
            .insert(key, ExitStatus::signaled(request.signal.get(), false)?);
        Ok(())
    }

    async fn wait_process(&self, request: AgentWaitProcessRequest) -> Result<ExitStatus> {
        let key = process_key(&request.target)?;
        let agent = self.state.lock().expect("agent state lock");
        if !agent.processes.contains_key(&key) {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest exec process does not exist",
            ));
        }
        agent.process_exits.get(&key).cloned().ok_or_else(|| {
            Error::new(
                ErrorCode::DeadlineExceeded,
                "test exec process has not exited",
            )
            .for_operation("agent-wait-process")
        })
    }

    async fn pause(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        self.set_paused(request, true)
    }

    async fn resume(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        self.set_paused(request, false)
    }

    async fn processes(&self, request: AgentProcessesRequest) -> Result<Vec<ProcessRecord>> {
        let agent = self.state.lock().expect("agent state lock");
        let state = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if state.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        let mut records = Vec::new();
        if state.status() != ContainerState::Stopped {
            records.push(ProcessRecord {
                target: ProcessTarget {
                    container: request.target.clone(),
                    process_id: ProcessId::init(),
                },
                pid: state.pid().and_then(|pid| u32::try_from(pid).ok()),
                terminal: false,
            });
        }
        for (key, process) in &agent.processes {
            if process.target().container == request.target
                && !agent.process_exits.contains_key(key)
            {
                records.push(ProcessRecord {
                    target: process.target().clone(),
                    pid: u32::try_from(process.pid()).ok(),
                    terminal: process.terminal(),
                });
            }
        }
        Ok(records)
    }

    async fn update(&self, request: AgentUpdateRequest) -> Result<AgentState> {
        let agent = self.state.lock().expect("agent state lock");
        let state = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if state.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        Ok(state.clone())
    }

    async fn stats(&self, request: AgentStatsRequest) -> Result<ContainerStats> {
        let agent = self.state.lock().expect("agent state lock");
        let state = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if state.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        Ok(ContainerStats {
            target: request.target,
            timestamp_unix_ns: 1,
            cpu: CpuStats {
                usage_ns: 30,
                user_ns: 10,
                system_ns: 20,
                throttled_ns: 0,
            },
            memory: MemoryStats {
                usage_bytes: 1_024,
                limit_bytes: Some(4_096),
                peak_bytes: Some(2_048),
            },
            process_count: u64::from(state.pid().is_some()),
            metrics: BTreeMap::from([("memory.events.oom_kill".to_string(), 0)]),
        })
    }

    async fn read_output(&self, request: AgentReadOutputRequest) -> Result<Vec<OutputChunk>> {
        let agent = self.state.lock().expect("agent state lock");
        ensure_test_process(&agent, &request.process)?;
        const OUTPUT: &[u8] = b"ready\n";
        let latest = OUTPUT.len() as u64 + 1;
        if request.after_sequence > latest {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "test output cursor is ahead of the stream",
            ));
        }

        let mut chunks = Vec::new();
        let mut cursor = request.after_sequence;
        if cursor < OUTPUT.len() as u64 {
            let offset = cursor as usize;
            let length = (request.max_bytes as usize).min(OUTPUT.len() - offset);
            if length > 0 {
                cursor += length as u64;
                chunks.push(OutputChunk {
                    sequence: cursor,
                    stream: OutputStream::Stdout,
                    data: OUTPUT[offset..offset + length].to_vec(),
                    eof: false,
                });
            }
        }
        if cursor == OUTPUT.len() as u64 {
            chunks.push(OutputChunk {
                sequence: latest,
                stream: OutputStream::Stdout,
                data: Vec::new(),
                eof: true,
            });
        }
        Ok(chunks)
    }

    async fn write_stdin(&self, request: AgentWriteStdinRequest) -> Result<()> {
        let key = process_key(&request.process)?;
        let mut agent = self.state.lock().expect("agent state lock");
        ensure_test_process(&agent, &request.process)?;
        if agent.stdin_closed.contains(&key) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "test process stdin is closed",
            ));
        }
        agent.stdin.entry(key).or_default().extend(request.data);
        Ok(())
    }

    async fn close_stdin(&self, request: AgentCloseStdinRequest) -> Result<()> {
        let key = process_key(&request.process)?;
        let mut agent = self.state.lock().expect("agent state lock");
        ensure_test_process(&agent, &request.process)?;
        agent.stdin_closed.insert(key);
        Ok(())
    }

    async fn resize(&self, request: AgentResizeRequest) -> Result<()> {
        let key = process_key(&request.process)?;
        let mut agent = self.state.lock().expect("agent state lock");
        ensure_test_process(&agent, &request.process)?;
        agent.terminal_sizes.insert(key, request.size);
        Ok(())
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        ensure_test_container(
            &self.state.lock().expect("agent state lock"),
            &request.target,
        )?;
        Ok(FileResponse {
            target: request.target,
            data: (request.op == FileOp::Download).then(String::new),
            size: 0,
        })
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        ensure_test_container(
            &self.state.lock().expect("agent state lock"),
            &request.target,
        )?;
        let entries = (request.op == FilesystemOp::ListDir)
            .then(|| FilesystemEntry {
                name: "agent.txt".to_string(),
                kind: FilesystemEntryKind::File,
                path: "/agent.txt".to_string(),
                size: 0,
                mode: 0o644,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified_seconds: 0,
                modified_nanos: 0,
                symlink_target: None,
                metadata: BTreeMap::new(),
            })
            .into_iter()
            .collect();
        Ok(FilesystemResponse {
            target: request.target,
            entry: None,
            entries,
        })
    }

    async fn delete(&self, request: AgentDeleteRequest) -> Result<()> {
        let mut agent = self.state.lock().expect("agent state lock");
        let current = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        agent.states.remove(&request.target.id);
        Ok(())
    }
}

fn ensure_test_container(agent: &TestAgentState, target: &ContainerTarget) -> Result<()> {
    let state = agent
        .states
        .get(&target.id)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
    if state.target() == target {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::Conflict,
            "guest container generation does not match",
        ))
    }
}

fn ensure_test_process(agent: &TestAgentState, target: &ProcessTarget) -> Result<()> {
    let state = agent
        .states
        .get(&target.container.id)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
    if state.target() != &target.container {
        return Err(Error::new(
            ErrorCode::Conflict,
            "guest container generation does not match",
        ));
    }
    if target.process_id.is_init() || agent.processes.contains_key(&process_key(target)?) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::NotFound,
            "guest exec process does not exist",
        ))
    }
}

impl TestAgent {
    fn set_paused(
        &self,
        request: AgentContainerOperationRequest,
        paused: bool,
    ) -> Result<AgentState> {
        let mut agent = self.state.lock().expect("agent state lock");
        let current = agent
            .states
            .get(&request.target.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest container generation does not match",
            ));
        }
        if current.status() != ContainerState::Running {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest freezer mutation requires a running container",
            ));
        }
        let state = AgentState::new_with_pause(
            request.target.clone(),
            current.status(),
            current.pid(),
            current.config_digest(),
            paused,
        )?;
        agent.states.insert(request.target.id, state.clone());
        Ok(state)
    }
}

fn identifier<T>(value: &str, constructor: impl FnOnce(String) -> a3s_oci_sdk::Result<T>) -> T {
    constructor(value.to_string()).unwrap_or_else(|error| panic!("valid identifier: {error}"))
}

fn container_id(value: &str) -> ContainerId {
    identifier(value, ContainerId::new)
}

fn operation_id(value: &str) -> OperationId {
    identifier(value, OperationId::new)
}

fn process_id(value: &str) -> ProcessId {
    identifier(value, ProcessId::new)
}

fn process_key(target: &ProcessTarget) -> Result<(ContainerId, Generation, ProcessId)> {
    let generation = target.container.generation.ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "test process target requires an exact generation",
        )
    })?;
    Ok((
        target.container.id.clone(),
        generation,
        target.process_id.clone(),
    ))
}

fn token(byte: u8) -> SessionToken {
    SessionToken::from_bytes([byte; 32]).expect("nonzero session token")
}

fn create_request() -> AgentCreateRequest {
    create_request_for("container-1", 1, "create-1")
}

fn create_request_for(container: &str, generation: u64, operation: &str) -> AgentCreateRequest {
    let directory = std::env::temp_dir().join(format!("a3s-agent-protocol-{container}"));
    let bundle = OciBundle::from_json(directory, TEST_CONFIG).expect("valid OCI bundle");
    AgentCreateRequest {
        context: OperationContext::new(operation_id(operation)),
        target: ContainerTarget::exact(container_id(container), Generation(generation)),
        bundle: crate::AgentBundle::new(
            &bundle,
            GuestPath::new(format!("/run/a3s/bundles/{container}")).expect("guest path"),
        ),
        io: ProcessIo::default(),
    }
}

fn exec_request(target: ContainerTarget, process_name: &str, operation: &str) -> AgentExecRequest {
    let process: Process = serde_json::from_str(
        r#"{
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh", "-c", "exit 0"],
            "cwd": "/",
            "env": ["A3S_EXEC_TEST=1"]
        }"#,
    )
    .expect("valid OCI exec process");
    AgentExecRequest {
        context: OperationContext::new(operation_id(operation)),
        target: ProcessTarget {
            container: target,
            process_id: process_id(process_name),
        },
        process,
        io: ProcessIo::default(),
    }
}

fn spawn_server(
    stream: DuplexStream,
    expected_token: SessionToken,
) -> tokio::task::JoinHandle<Result<()>> {
    spawn_server_with_agent(stream, expected_token, Arc::new(TestAgent::default()))
}

fn spawn_server_with_agent(
    stream: DuplexStream,
    expected_token: SessionToken,
    agent: Arc<TestAgent>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(serve_agent_connection(stream, expected_token, agent))
}

#[derive(Debug)]
struct DropObservedStream {
    inner: DuplexStream,
    dropped: Arc<AtomicBool>,
}

impl DropObservedStream {
    fn new(inner: DuplexStream, dropped: Arc<AtomicBool>) -> Self {
        Self { inner, dropped }
    }
}

impl Drop for DropObservedStream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for DropObservedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for DropObservedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}
