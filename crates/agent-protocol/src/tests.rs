use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerStats, ContainerTarget, CpuStats, DeleteMode, Error,
    ErrorCode, ExitStatus, Generation, IoMode, MemoryStats, OciBundle, OperationContext,
    OperationId, OutputChunk, OutputStream, ProcessId, ProcessIo, ProcessRecord, ProcessTarget,
    Result, Signal, TerminalSize,
};
use tokio::io::{AsyncWriteExt, DuplexStream};

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

#[tokio::test]
async fn negotiates_and_round_trips_the_core_oci_lifecycle() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(7));
    let client = AgentClient::connect_for_test(host, token(7), 1, 1)
        .await
        .expect("connect agent client");
    assert_eq!(client.hello().selected_version(), 1);
    assert_eq!(client.hello().capabilities().operations().len(), 5);

    let create = create_request();
    let digest = create.bundle.config_digest().to_string();
    let target = create.target.clone();
    let created = client.create(create).await.expect("agent create");
    assert_eq!(created.status(), ContainerState::Created);
    assert_eq!(created.pid(), Some(101));
    assert_eq!(
        client
            .state(AgentStateRequest {
                target: target.clone()
            })
            .await
            .expect("agent state"),
        created
    );

    let running = client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("start-1")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("agent start");
    assert_eq!(running.status(), ContainerState::Running);

    let stopped = client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("kill-1")),
            target: target.clone(),
            signal: Signal::new(15).expect("signal"),
            all: false,
        })
        .await
        .expect("agent kill");
    assert_eq!(stopped.status(), ContainerState::Stopped);

    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("delete-1")),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("agent delete");

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean server shutdown");
}

#[tokio::test]
async fn protocol_v2_wait_returns_and_replays_the_exact_exit_status() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(18));
    let client = AgentClient::connect_for_test(host, token(18), 2, 2)
        .await
        .expect("connect protocol-v2 client");
    assert_eq!(client.hello().selected_version(), 2);
    assert_eq!(
        client.hello().capabilities().operations(),
        &[
            crate::AgentOperation::Create,
            crate::AgentOperation::State,
            crate::AgentOperation::Start,
            crate::AgentOperation::Kill,
            crate::AgentOperation::Delete,
            crate::AgentOperation::Wait,
        ]
    );

    let create = create_request_for("wait-container", 1, "wait-create");
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    client.create(create).await.expect("create wait container");
    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("wait-start")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("start wait container");
    client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("wait-kill")),
            target: target.clone(),
            signal: Signal::new(9).expect("signal"),
            all: false,
        })
        .await
        .expect("kill wait container");
    let request = AgentWaitRequest {
        target: target.clone(),
        timeout_ms: Some(1_000),
    };
    let expected = ExitStatus::signaled(9, false).expect("exit status");
    assert_eq!(
        client.wait(request.clone()).await.expect("first wait"),
        expected
    );
    assert_eq!(client.wait(request).await.expect("repeated wait"), expected);

    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("wait-delete")),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete wait container");
    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v2 server shutdown");
}

#[tokio::test]
async fn protocol_v1_rejects_a_forged_wait_before_service_dispatch() {
    let (mut host, guest) = tokio::io::duplex(64 * 1024);
    let agent = Arc::new(TestAgent::default());
    let expected_token = token(19);
    let server = spawn_server_with_agent(guest, expected_token.clone(), agent.clone());

    write_frame(
        &mut host,
        &HostHello {
            protocols: ProtocolRange { min: 1, max: 1 },
            token: expected_token,
        },
    )
    .await
    .expect("write protocol-v1 hello");
    let hello: HelloOutcome = read_frame(&mut host)
        .await
        .expect("read protocol-v1 hello")
        .expect("server returned protocol-v1 hello");
    let HelloOutcome::Accepted { hello } = hello else {
        panic!("protocol-v1 negotiation was rejected");
    };
    assert_eq!(hello.selected_version(), 1);
    assert!(!hello
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::Wait));

    write_frame(
        &mut host,
        &RequestEnvelope {
            version: 1,
            request_id: 41,
            request: AgentRequest::Wait(AgentWaitRequest {
                target: ContainerTarget::exact(container_id("forged-wait"), Generation(1)),
                timeout_ms: Some(1),
            }),
        },
    )
    .await
    .expect("write forged protocol-v1 wait");
    let response: ResponseEnvelope = read_frame(&mut host)
        .await
        .expect("read forged wait response")
        .expect("server returned forged wait response");
    assert_eq!(response.version, 1);
    assert_eq!(response.request_id, 41);
    let ResponseOutcome::Failed { error } = response.outcome else {
        panic!("forged protocol-v1 wait unexpectedly succeeded");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(agent.wait_dispatches.load(Ordering::SeqCst), 0);

    drop(host);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v1 server shutdown");
}

#[tokio::test]
async fn transports_two_independently_fenced_container_generations() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(17));
    let client = AgentClient::connect(host, token(17))
        .await
        .expect("connect multi-container client");

    let create_a = create_request_for("multi-a", 1, "multi-create-a-1");
    let create_b = create_request_for("multi-b", 1, "multi-create-b-1");
    let target_a1 = create_a.target.clone();
    let target_b = create_b.target.clone();
    let digest_a = create_a.bundle.config_digest().to_string();
    let digest_b = create_b.bundle.config_digest().to_string();
    let created_a = client.create(create_a).await.expect("create container A");
    let created_b = client.create(create_b).await.expect("create container B");
    assert_eq!(created_a.status(), ContainerState::Created);
    assert_eq!(created_b.status(), ContainerState::Created);
    assert!(created_a.pid().is_some_and(|pid| pid > 0));
    assert!(created_b.pid().is_some_and(|pid| pid > 0));
    assert_ne!(created_a.pid(), created_b.pid());

    let running_a = client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("multi-start-a-1")),
            target: target_a1.clone(),
            expected_config_digest: digest_a,
        })
        .await
        .expect("start container A");
    assert_eq!(running_a.status(), ContainerState::Running);
    assert_eq!(
        client
            .state(AgentStateRequest {
                target: target_b.clone()
            })
            .await
            .expect("container B remains visible"),
        created_b
    );

    client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("multi-kill-a-1")),
            target: target_a1.clone(),
            signal: Signal::new(15).expect("signal"),
            all: false,
        })
        .await
        .expect("kill container A");
    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("multi-delete-a-1")),
            target: target_a1.clone(),
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete container A");
    assert_eq!(
        client
            .state(AgentStateRequest {
                target: target_b.clone()
            })
            .await
            .expect("container B survives A delete"),
        created_b
    );

    let stale = client
        .create(create_request_for("multi-a", 1, "multi-stale-a-1"))
        .await
        .expect_err("stale generation must fail");
    assert_eq!(stale.code, ErrorCode::Conflict);
    let create_a2 = create_request_for("multi-a", 2, "multi-create-a-2");
    let target_a2 = create_a2.target.clone();
    let recreated_a = client
        .create(create_a2)
        .await
        .expect("recreate container A");
    assert_eq!(recreated_a.status(), ContainerState::Created);
    let stale_state = client
        .state(AgentStateRequest { target: target_a1 })
        .await
        .expect_err("old generation must remain fenced");
    assert_eq!(stale_state.code, ErrorCode::Conflict);
    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("multi-delete-a-2")),
            target: target_a2,
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete recreated container A");

    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("multi-start-b-1")),
            target: target_b.clone(),
            expected_config_digest: digest_b,
        })
        .await
        .expect("start container B");
    client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("multi-kill-b-1")),
            target: target_b.clone(),
            signal: Signal::new(15).expect("signal"),
            all: false,
        })
        .await
        .expect("kill container B");
    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("multi-delete-b-1")),
            target: target_b,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete container B");

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean multi-container server shutdown");
}

#[tokio::test]
async fn rejects_wrong_session_tokens_and_incompatible_versions() {
    let (host, guest) = tokio::io::duplex(64 * 1024);
    let server = spawn_server(guest, token(7));
    let error = AgentClient::connect(host, token(8))
        .await
        .expect_err("wrong token must fail");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        server
            .await
            .expect("server task")
            .expect_err("server rejects token")
            .code,
        ErrorCode::PermissionDenied
    );

    let (host, guest) = tokio::io::duplex(64 * 1024);
    let server = spawn_server(guest, token(9));
    let error = AgentClient::connect_for_test(host, token(9), 8, 8)
        .await
        .expect_err("incompatible version must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        server
            .await
            .expect("server task")
            .expect_err("server rejects version")
            .code,
        ErrorCode::FailedPrecondition
    );
}

#[tokio::test]
async fn rejects_oversized_frames_before_reading_the_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&11_u32.to_be_bytes())
        .await
        .expect("write frame header");

    let error = read_frame_for_test::<serde_json::Value, _>(&mut reader, 10)
        .await
        .expect_err("oversized frame must fail from its header");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn rejects_tampered_bundle_digests_before_guest_dispatch() {
    let mut encoded = serde_json::to_value(create_request()).expect("encode request");
    encoded["bundle"]["configDigest"] =
        serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
    let request: AgentCreateRequest = serde_json::from_value(encoded).expect("decode request");
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(10));
    let client = AgentClient::connect(host, token(10))
        .await
        .expect("connect agent client");

    let error = client
        .create(request)
        .await
        .expect_err("tampered digest must fail locally");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean server shutdown");
}

#[tokio::test]
async fn correlation_failure_permanently_poisoned_the_client_connection() {
    let (host, mut guest) = tokio::io::duplex(1024 * 1024);
    let malicious = tokio::spawn(async move {
        let hello: HostHello = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing hello"))?;
        let capabilities = AgentCapabilities::core("malicious-test", std::env::consts::ARCH)?;
        write_frame(
            &mut guest,
            &HelloOutcome::Accepted {
                hello: AgentHello::new(1, capabilities),
            },
        )
        .await?;
        let request: RequestEnvelope = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing request"))?;
        let AgentRequest::Create(create) = request.request else {
            return Err(Error::new(ErrorCode::Internal, "expected create"));
        };
        let state = AgentState::new(
            create.target,
            ContainerState::Created,
            Some(101),
            create.bundle.config_digest(),
        )?;
        write_frame(
            &mut guest,
            &ResponseEnvelope {
                version: 1,
                request_id: request.request_id + 1,
                outcome: ResponseOutcome::Succeeded {
                    response: AgentResponse::State(state),
                },
            },
        )
        .await?;
        let _ = hello;
        Ok::<_, Error>(())
    });

    let client = AgentClient::connect(host, token(11))
        .await
        .expect("connect malicious peer");
    let error = client
        .create(create_request())
        .await
        .expect_err("mismatched response ID must fail");
    assert_eq!(error.code, ErrorCode::Conflict);
    let error = client
        .create(create_request())
        .await
        .expect_err("connection must stay poisoned");
    assert_eq!(error.code, ErrorCode::Unavailable);
    malicious
        .await
        .expect("malicious task")
        .expect("malicious response written");
}

#[test]
fn secrets_are_redacted_and_guest_paths_are_normalized() {
    assert_eq!(format!("{:?}", token(12)), "SessionToken([REDACTED])");
    for path in [
        "run/a3s",
        "/run//a3s",
        "/run/../a3s",
        "/run/./a3s",
        "/run/a3s/",
        r"/run\a3s",
    ] {
        assert!(GuestPath::new(path).is_err(), "{path:?} must be rejected");
    }
    assert!(GuestPath::new("/run/a3s").is_ok());
}
