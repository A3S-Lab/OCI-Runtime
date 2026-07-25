use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::{
    Arch, ContainerState, LinuxNamespaceType, LinuxResources, LinuxSeccompAction, Process,
};
use a3s_oci_sdk::{
    async_trait, CloseStdinRequest, ContainerId, ContainerOperationRequest, ContainerStats,
    ContainerTarget, CpuStats, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    ExecRequest, ExitStatus, Generation, IoMode, IsolationRequest, KillRequest, ListRequest,
    MemoryStats, OciBundle, OciRuntimeService, OciSchemaValidator, OperationContext, OperationId,
    OutputChunk, OutputStream, ProcessId, ProcessIo, ProcessRecord, ProcessTarget,
    ProcessesRequest, ReadOutputRequest, Result, RuntimeOperation, Signal, SignalProcessRequest,
    StartRequest, StateRequest, StatsRequest, TrustDomainId, UpdateRequest, WaitProcessRequest,
    WaitRequest, WriteStdinRequest,
};

use super::{HostRuntimeService, RECOGNIZED_LINUX_MOUNT_OPTIONS, SUPPORTED_LINUX_CAPABILITIES};
use crate::{
    DriverContainerOperationRequest, DriverCreateRequest, DriverDeleteRequest, DriverExecRequest,
    DriverKillRequest, DriverProcess, DriverReadOutputRequest, DriverSignalProcessRequest,
    DriverStartRequest, DriverState, DriverUpdateRequest, DriverWaitProcessRequest,
    DriverWaitRequest, DriverWriteStdinRequest, RuntimeDriver,
};

mod fault_matrix;
mod io_operations;
mod process_operations;
mod resource_operations;

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum DriverCall {
    Create(DriverCreateRequest),
    State(ContainerTarget),
    Start(DriverStartRequest),
    Kill(DriverKillRequest),
    Delete(DriverDeleteRequest),
    Wait(DriverWaitRequest),
    Exec(DriverExecRequest),
    SignalProcess(DriverSignalProcessRequest),
    WaitProcess(DriverWaitProcessRequest),
    Pause(DriverContainerOperationRequest),
    Resume(DriverContainerOperationRequest),
    Processes(ContainerTarget),
    Update(DriverUpdateRequest),
    Stats(ContainerTarget),
    ReadOutput(DriverReadOutputRequest),
    WriteStdin(DriverWriteStdinRequest),
    CloseStdin(ProcessTarget),
}

type DriverProcessKey = (ContainerId, Generation, ProcessId);
type DriverProcessState = (DriverProcess, Option<ExitStatus>);

#[derive(Debug)]
struct RecordingDriver {
    capability: DriverCapability,
    operations: Vec<RuntimeOperation>,
    calls: Mutex<Vec<DriverCall>>,
    states: Mutex<HashMap<ContainerId, (Generation, DriverState)>>,
    exits: Mutex<HashMap<ContainerId, ExitStatus>>,
    processes: Mutex<HashMap<DriverProcessKey, DriverProcessState>>,
    exec_replays: Mutex<HashMap<OperationId, (DriverExecRequest, DriverProcess)>>,
    signal_process_replays: Mutex<HashMap<OperationId, DriverSignalProcessRequest>>,
    update_replays: Mutex<HashMap<OperationId, DriverUpdateRequest>>,
    output_responses: Mutex<VecDeque<Vec<OutputChunk>>>,
    failures: Mutex<HashMap<&'static str, Vec<Error>>>,
}

impl RecordingDriver {
    fn supported() -> Self {
        Self {
            capability: DriverCapability {
                driver: DriverKind::LibkrunWhpx,
                status: CapabilityStatus::Available,
                readiness: DriverReadiness::Supported,
                isolation_classes: vec![IsolationClass::DedicatedVm],
                reason: None,
                evidence: BTreeMap::from([("test-driver".to_string(), "in-process".to_string())]),
            },
            operations: vec![
                RuntimeOperation::Create,
                RuntimeOperation::State,
                RuntimeOperation::Start,
                RuntimeOperation::Kill,
                RuntimeOperation::Delete,
                RuntimeOperation::Wait,
            ],
            calls: Mutex::new(Vec::new()),
            states: Mutex::new(HashMap::new()),
            exits: Mutex::new(HashMap::new()),
            processes: Mutex::new(HashMap::new()),
            exec_replays: Mutex::new(HashMap::new()),
            signal_process_replays: Mutex::new(HashMap::new()),
            update_replays: Mutex::new(HashMap::new()),
            output_responses: Mutex::new(VecDeque::new()),
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn probe_only() -> Self {
        let mut driver = Self::supported();
        driver.capability.readiness = DriverReadiness::ProbeOnly;
        driver
    }

    fn without_wait() -> Self {
        let mut driver = Self::supported();
        driver.operations.pop();
        driver
    }

    fn with_process_operations() -> Self {
        let mut driver = Self::supported();
        driver.operations.extend([
            RuntimeOperation::Exec,
            RuntimeOperation::SignalProcess,
            RuntimeOperation::WaitProcess,
        ]);
        driver
    }

    fn with_control_operations() -> Self {
        let mut driver = Self::with_process_operations();
        driver.operations.extend([
            RuntimeOperation::Pause,
            RuntimeOperation::Resume,
            RuntimeOperation::Processes,
            RuntimeOperation::Update,
            RuntimeOperation::Stats,
            RuntimeOperation::ReadOutput,
            RuntimeOperation::WriteStdin,
            RuntimeOperation::CloseStdin,
        ]);
        driver
    }

    fn calls(&self) -> Vec<DriverCall> {
        self.calls.lock().expect("driver calls lock").clone()
    }

    fn fail_next(&self, operation: &'static str, error: Error) {
        self.failures
            .lock()
            .expect("driver failures lock")
            .entry(operation)
            .or_default()
            .push(error);
    }

    fn queue_output(&self, chunks: Vec<OutputChunk>) {
        self.output_responses
            .lock()
            .expect("driver output responses lock")
            .push_back(chunks);
    }

    fn take_failure(&self, operation: &'static str) -> Option<Error> {
        let mut failures = self.failures.lock().expect("driver failures lock");
        let queue = failures.get_mut(operation)?;
        if queue.is_empty() {
            None
        } else {
            Some(queue.remove(0))
        }
    }

    fn exact_generation(target: &ContainerTarget) -> Result<Generation> {
        target.generation.ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "driver requests must carry an exact generation",
            )
        })
    }

    fn process_key(target: &ProcessTarget) -> Result<(ContainerId, Generation, ProcessId)> {
        Ok((
            target.container.id.clone(),
            Self::exact_generation(&target.container)?,
            target.process_id.clone(),
        ))
    }
}

#[async_trait]
impl RuntimeDriver for RecordingDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &self.operations
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Create(request.clone()));
        if let Some(error) = self.take_failure("create") {
            return Err(error);
        }
        let generation = Self::exact_generation(&request.target)?;
        let state = DriverState::created(4_242)?;
        self.states
            .lock()
            .expect("driver states lock")
            .insert(request.target.id.clone(), (generation, state));
        self.exits
            .lock()
            .expect("driver exits lock")
            .remove(&request.target.id);
        Ok(state)
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::State(target.clone()));
        let generation = Self::exact_generation(&target)?;
        let states = self.states.lock().expect("driver states lock");
        let (actual_generation, state) = states.get(&target.id).copied().ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "driver container does not exist")
                .for_operation("driver-state")
        })?;
        if generation != actual_generation {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-state"),
            );
        }
        Ok(state)
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Start(request.clone()));
        if let Some(error) = self.take_failure("start") {
            return Err(error);
        }
        let generation = Self::exact_generation(&request.target)?;
        let state = DriverState::running(4_242)?;
        self.states
            .lock()
            .expect("driver states lock")
            .insert(request.target.id, (generation, state));
        Ok(state)
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Kill(request.clone()));
        if let Some(error) = self.take_failure("kill") {
            return Err(error);
        }
        let generation = Self::exact_generation(&request.target)?;
        let state = DriverState::stopped();
        self.states
            .lock()
            .expect("driver states lock")
            .insert(request.target.id.clone(), (generation, state));
        self.exits.lock().expect("driver exits lock").insert(
            request.target.id,
            ExitStatus::signaled(request.signal.get(), false)?,
        );
        Ok(state)
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Delete(request.clone()));
        if let Some(error) = self.take_failure("delete") {
            return Err(error);
        }
        self.states
            .lock()
            .expect("driver states lock")
            .remove(&request.target.id);
        self.exits
            .lock()
            .expect("driver exits lock")
            .remove(&request.target.id);
        self.processes
            .lock()
            .expect("driver processes lock")
            .retain(|(id, _, _), _| id != &request.target.id);
        Ok(())
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Wait(request.clone()));
        if let Some(error) = self.take_failure("wait") {
            return Err(error);
        }
        let generation = Self::exact_generation(&request.target)?;
        let states = self.states.lock().expect("driver states lock");
        let (actual_generation, state) =
            states.get(&request.target.id).copied().ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "driver container does not exist")
                    .for_operation("driver-wait")
            })?;
        if generation != actual_generation {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-wait"),
            );
        }
        if state.status() != ContainerState::Stopped {
            return Err(Error::new(
                ErrorCode::DeadlineExceeded,
                "driver process is still running",
            )
            .for_operation("driver-wait")
            .retryable(true));
        }
        drop(states);
        self.exits
            .lock()
            .expect("driver exits lock")
            .get(&request.target.id)
            .cloned()
            .ok_or_else(|| {
                Error::new(ErrorCode::Internal, "driver lost the init exit status")
                    .for_operation("driver-wait")
            })
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Exec(request.clone()));
        if let Some((recorded, response)) = self
            .exec_replays
            .lock()
            .expect("driver exec replay lock")
            .get(&request.context.operation_id)
        {
            if recorded != &request {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    "driver exec operation ID was reused for a different request",
                )
                .for_operation("driver-exec"));
            }
            return Ok(*response);
        }
        if let Some(error) = self.take_failure("exec") {
            return Err(error);
        }
        let key = Self::process_key(&request.target)?;
        let states = self.states.lock().expect("driver states lock");
        let (generation, state) = states.get(&key.0).copied().ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "driver container does not exist")
                .for_operation("driver-exec")
        })?;
        if generation != key.1 {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-exec"),
            );
        }
        if state.status() != ContainerState::Running {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "driver container is not running",
            )
            .for_operation("driver-exec"));
        }
        drop(states);

        let mut processes = self.processes.lock().expect("driver processes lock");
        if processes.contains_key(&key) {
            return Err(
                Error::new(ErrorCode::AlreadyExists, "driver process already exists")
                    .for_operation("driver-exec"),
            );
        }
        let pid = 5_000_i32
            .checked_add(i32::try_from(processes.len()).map_err(|error| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    format!("driver process count does not fit PID allocator: {error}"),
                )
                .for_operation("driver-exec")
            })?)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "driver process PID space exhausted",
                )
                .for_operation("driver-exec")
            })?;
        let process = DriverProcess::new(pid, request.process.terminal().unwrap_or(false))?;
        processes.insert(key, (process, None));
        self.exec_replays
            .lock()
            .expect("driver exec replay lock")
            .insert(request.context.operation_id.clone(), (request, process));
        Ok(process)
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::SignalProcess(request.clone()));
        if let Some(recorded) = self
            .signal_process_replays
            .lock()
            .expect("driver signal replay lock")
            .get(&request.context.operation_id)
        {
            if recorded != &request {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    "driver signal operation ID was reused for a different request",
                )
                .for_operation("driver-signal-process"));
            }
            return Ok(());
        }
        if let Some(error) = self.take_failure("signal-process") {
            return Err(error);
        }
        let key = Self::process_key(&request.target)?;
        if key.2.is_init() {
            let mut states = self.states.lock().expect("driver states lock");
            let (generation, state) = states.get_mut(&key.0).ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "driver container does not exist")
                    .for_operation("driver-signal-process")
            })?;
            if *generation != key.1 {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "driver container generation mismatch",
                )
                .for_operation("driver-signal-process"));
            }
            if state.status() == ContainerState::Stopped {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    "driver init process already exited",
                )
                .for_operation("driver-signal-process"));
            }
            *state = DriverState::stopped();
            self.exits
                .lock()
                .expect("driver exits lock")
                .insert(key.0, ExitStatus::signaled(request.signal.get(), false)?);
            self.signal_process_replays
                .lock()
                .expect("driver signal replay lock")
                .insert(request.context.operation_id.clone(), request);
            return Ok(());
        }

        let mut processes = self.processes.lock().expect("driver processes lock");
        let (_, exit) = processes.get_mut(&key).ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "driver process does not exist")
                .for_operation("driver-signal-process")
        })?;
        if exit.is_some() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "driver process already exited",
            )
            .for_operation("driver-signal-process"));
        }
        *exit = Some(ExitStatus::signaled(request.signal.get(), false)?);
        self.signal_process_replays
            .lock()
            .expect("driver signal replay lock")
            .insert(request.context.operation_id.clone(), request);
        Ok(())
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::WaitProcess(request.clone()));
        if let Some(error) = self.take_failure("wait-process") {
            return Err(error);
        }
        let key = Self::process_key(&request.target)?;
        if key.2.is_init() {
            let states = self.states.lock().expect("driver states lock");
            let (generation, _) = states.get(&key.0).copied().ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "driver container does not exist")
                    .for_operation("driver-wait-process")
            })?;
            if generation != key.1 {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "driver container generation mismatch",
                )
                .for_operation("driver-wait-process"));
            }
            drop(states);
            return self
                .exits
                .lock()
                .expect("driver exits lock")
                .get(&key.0)
                .cloned()
                .ok_or_else(|| {
                    Error::new(ErrorCode::DeadlineExceeded, "driver init is still running")
                        .for_operation("driver-wait-process")
                        .retryable(true)
                });
        }
        self.processes
            .lock()
            .expect("driver processes lock")
            .get(&key)
            .ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "driver process does not exist")
                    .for_operation("driver-wait-process")
            })?
            .1
            .clone()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::DeadlineExceeded,
                    "driver process is still running",
                )
                .for_operation("driver-wait-process")
                .retryable(true)
            })
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Pause(request.clone()));
        if let Some(error) = self.take_failure("pause") {
            return Err(error);
        }
        self.set_paused(&request.target, true)
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Resume(request.clone()));
        if let Some(error) = self.take_failure("resume") {
            return Err(error);
        }
        self.set_paused(&request.target, false)
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Processes(target.clone()));
        if let Some(error) = self.take_failure("processes") {
            return Err(error);
        }
        let generation = Self::exact_generation(&target)?;
        let states = self.states.lock().expect("driver states lock");
        let (actual_generation, state) = states.get(&target.id).copied().ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "driver container does not exist")
                .for_operation("driver-processes")
        })?;
        if generation != actual_generation {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-processes"),
            );
        }
        let mut records = Vec::new();
        if state.status() != ContainerState::Stopped {
            records.push(ProcessRecord {
                target: ProcessTarget {
                    container: target.clone(),
                    process_id: ProcessId::init(),
                },
                pid: state.pid().and_then(|pid| u32::try_from(pid).ok()),
                terminal: false,
            });
        }
        drop(states);
        for ((id, process_generation, process_id), (process, exit)) in
            self.processes.lock().expect("driver processes lock").iter()
        {
            if id == &target.id && *process_generation == generation && exit.is_none() {
                records.push(ProcessRecord {
                    target: ProcessTarget {
                        container: target.clone(),
                        process_id: process_id.clone(),
                    },
                    pid: u32::try_from(process.pid()).ok(),
                    terminal: process.terminal(),
                });
            }
        }
        Ok(records)
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Update(request.clone()));
        let recorded = self
            .update_replays
            .lock()
            .expect("driver update replay lock")
            .get(&request.context.operation_id)
            .cloned();
        if let Some(recorded) = recorded {
            if recorded != request {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    "driver update operation ID was reused for a different request",
                )
                .for_operation("driver-update"));
            }
        } else {
            if let Some(error) = self.take_failure("update") {
                return Err(error);
            }
            self.update_replays
                .lock()
                .expect("driver update replay lock")
                .insert(request.context.operation_id.clone(), request.clone());
        }
        let generation = Self::exact_generation(&request.target)?;
        let states = self.states.lock().expect("driver states lock");
        let (actual_generation, state) =
            states.get(&request.target.id).copied().ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "driver container does not exist")
                    .for_operation("driver-update")
            })?;
        if generation != actual_generation {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-update"),
            );
        }
        if state.status() == ContainerState::Stopped {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "driver cannot update a stopped container",
            )
            .for_operation("driver-update"));
        }
        Ok(state)
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Stats(target.clone()));
        if let Some(error) = self.take_failure("stats") {
            return Err(error);
        }
        let generation = Self::exact_generation(&target)?;
        let states = self.states.lock().expect("driver states lock");
        let (actual_generation, state) = states.get(&target.id).copied().ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "driver container does not exist")
                .for_operation("driver-stats")
        })?;
        if generation != actual_generation {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-stats"),
            );
        }
        Ok(ContainerStats {
            target,
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
            process_count: u64::from(state.status() != ContainerState::Stopped),
            metrics: BTreeMap::from([("memory.events.oom_kill".to_string(), 0)]),
        })
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::ReadOutput(request.clone()));
        if let Some(error) = self.take_failure("read-output") {
            return Err(error);
        }
        if let Some(chunks) = self
            .output_responses
            .lock()
            .expect("driver output responses lock")
            .pop_front()
        {
            return Ok(chunks);
        }
        let sequence = request.after_sequence.checked_add(1).ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "test driver output sequence space is exhausted",
            )
        })?;
        Ok(vec![OutputChunk {
            sequence,
            stream: OutputStream::Stdout,
            data: Vec::new(),
            eof: true,
        }])
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::WriteStdin(request));
        if let Some(error) = self.take_failure("write-stdin") {
            return Err(error);
        }
        Ok(())
    }

    async fn close_stdin(&self, target: ProcessTarget) -> Result<()> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::CloseStdin(target));
        if let Some(error) = self.take_failure("close-stdin") {
            return Err(error);
        }
        Ok(())
    }
}

impl RecordingDriver {
    fn set_paused(&self, target: &ContainerTarget, paused: bool) -> Result<DriverState> {
        let generation = Self::exact_generation(target)?;
        let mut states = self.states.lock().expect("driver states lock");
        let (actual_generation, state) = states.get_mut(&target.id).ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "driver container does not exist")
                .for_operation("driver-freezer")
        })?;
        if generation != *actual_generation {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-freezer"),
            );
        }
        if state.status() != ContainerState::Running {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "driver freezer requires a running container",
            )
            .for_operation("driver-freezer"));
        }
        *state = state.with_paused(paused)?;
        Ok(*state)
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

fn create_request(bundle_directory: &Path, operation: &str) -> CreateRequest {
    CreateRequest {
        context: OperationContext::new(operation_id(operation)),
        id: container_id("sdk-container"),
        bundle: OciBundle::from_json(bundle_directory.to_path_buf(), TEST_CONFIG)
            .expect("valid OCI bundle"),
        isolation: IsolationRequest::DedicatedVm,
        io: ProcessIo::default(),
    }
}

fn exec_request(container: ContainerTarget, operation: &str, process_id: &str) -> ExecRequest {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", "while :; do :; done"],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .expect("valid exec process");
    ExecRequest {
        context: OperationContext::new(operation_id(operation)),
        container,
        process_id: ProcessId::new(process_id).expect("process ID"),
        process,
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    }
}

fn update_request(target: ContainerTarget, operation: &str) -> UpdateRequest {
    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "memory": {"limit": 4096},
        "cpu": {"shares": 1024},
        "pids": {"limit": 16}
    }))
    .expect("valid resource update");
    UpdateRequest {
        context: OperationContext::new(operation_id(operation)),
        target,
        resources,
    }
}

async fn open_service(
    temporary: &tempfile::TempDir,
    driver: Arc<RecordingDriver>,
) -> HostRuntimeService {
    HostRuntimeService::open(temporary.path().join("state"), driver)
        .await
        .expect("open host runtime")
}

#[tokio::test]
async fn reports_only_operations_that_are_currently_implemented() {
    let info = HostRuntimeService::new()
        .features()
        .await
        .expect("feature discovery must succeed");

    assert_eq!(info.operations, vec![RuntimeOperation::Features]);
    assert_eq!(info.oci.oci_version_min(), "1.0.0");
    assert_eq!(info.oci.oci_version_max(), "1.3.0");
    assert_eq!(info.oci.hooks().as_deref(), Some([].as_slice()));
    assert_eq!(
        info.oci.mount_options().as_deref(),
        Some(
            RECOGNIZED_LINUX_MOUNT_OPTIONS
                .iter()
                .map(|option| (*option).to_string())
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    let linux = info.oci.linux().as_ref().expect("Linux feature report");
    assert_eq!(
        linux.namespaces().as_deref(),
        Some(
            [
                LinuxNamespaceType::Cgroup,
                LinuxNamespaceType::Ipc,
                LinuxNamespaceType::Mount,
                LinuxNamespaceType::Network,
                LinuxNamespaceType::Pid,
                LinuxNamespaceType::Time,
                LinuxNamespaceType::User,
                LinuxNamespaceType::Uts,
            ]
            .as_slice()
        )
    );
    assert_eq!(
        linux.capabilities().as_deref(),
        Some(
            SUPPORTED_LINUX_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    let cgroup = linux.cgroup().as_ref().expect("cgroup feature report");
    assert_eq!(*cgroup.v1(), Some(false));
    assert_eq!(*cgroup.v2(), Some(true));
    let seccomp = linux.seccomp().as_ref().expect("seccomp feature report");
    assert_eq!(*seccomp.enabled(), Some(true));
    assert_eq!(
        seccomp.archs().as_deref(),
        Some([Arch::ScmpArchAarch64, Arch::ScmpArchX86_64].as_slice())
    );
    assert!(seccomp
        .actions()
        .as_deref()
        .expect("seccomp actions")
        .contains(&LinuxSeccompAction::ScmpActKillProcess));
    assert!(!seccomp
        .actions()
        .as_deref()
        .expect("seccomp actions")
        .contains(&LinuxSeccompAction::ScmpActNotify));
    assert_eq!(seccomp.supported_flags().as_deref(), Some([].as_slice()));
    assert_eq!(
        *linux
            .mount_extensions()
            .as_ref()
            .expect("mount extensions")
            .idmap()
            .as_ref()
            .expect("ID-map feature")
            .enabled(),
        Some(true)
    );
    OciSchemaValidator::new()
        .expect("compile pinned schemas")
        .validate_features(&info.oci)
        .expect("runtime feature report must match the pinned OCI schema");
}

#[tokio::test]
async fn rejects_invalid_driver_operation_inventories_before_opening_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let inventories = [
        (
            "missing-core",
            vec![
                RuntimeOperation::State,
                RuntimeOperation::Start,
                RuntimeOperation::Kill,
                RuntimeOperation::Delete,
            ],
        ),
        (
            "duplicate",
            vec![
                RuntimeOperation::Create,
                RuntimeOperation::State,
                RuntimeOperation::Start,
                RuntimeOperation::Kill,
                RuntimeOperation::Delete,
                RuntimeOperation::Delete,
            ],
        ),
        (
            "unsupported",
            vec![
                RuntimeOperation::Create,
                RuntimeOperation::State,
                RuntimeOperation::Start,
                RuntimeOperation::Kill,
                RuntimeOperation::Delete,
                RuntimeOperation::List,
            ],
        ),
    ];

    for (name, operations) in inventories {
        let root = temporary.path().join(name);
        let mut driver = RecordingDriver::supported();
        driver.operations = operations;
        let error = HostRuntimeService::open(&root, Arc::new(driver))
            .await
            .expect_err("invalid driver operation inventory must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(!root.exists(), "{name} created durable state");
    }
}

#[tokio::test]
async fn incomplete_lifecycle_fails_explicitly() {
    let error = HostRuntimeService::new()
        .list(ListRequest::default())
        .await
        .expect_err("list must remain disabled before durable state exists");

    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(error.operation.as_deref(), Some("list"));
}

#[tokio::test]
async fn rust_sdk_lifecycle_is_durable_and_exactly_replayed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let info = service.features().await.expect("configured features");
    assert_eq!(
        info.operations,
        vec![
            RuntimeOperation::Features,
            RuntimeOperation::Create,
            RuntimeOperation::State,
            RuntimeOperation::Start,
            RuntimeOperation::Kill,
            RuntimeOperation::Delete,
            RuntimeOperation::Wait,
        ]
    );

    let create = create_request(&bundle_directory, "create-1");
    let created = service.create(create.clone()).await.expect("create");
    assert_eq!(*created.state.status(), ContainerState::Created);
    assert_eq!(*created.state.pid(), Some(4_242));
    assert_eq!(created.generation, Generation(1));
    assert_eq!(
        service.create(create.clone()).await.expect("replay create"),
        created
    );

    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    assert_eq!(
        service
            .state(StateRequest {
                target: target.clone()
            })
            .await
            .expect("query created state"),
        created
    );

    let start = StartRequest {
        context: OperationContext::new(operation_id("start-1")),
        target: target.clone(),
    };
    let running = service.start(start.clone()).await.expect("start");
    assert_eq!(*running.state.status(), ContainerState::Running);
    assert_eq!(service.start(start).await.expect("replay start"), running);

    let kill = KillRequest {
        context: OperationContext::new(operation_id("kill-1")),
        target: target.clone(),
        signal: Signal::new(15).expect("signal"),
        all: true,
    };
    let stopped = service.kill(kill.clone()).await.expect("kill");
    assert_eq!(*stopped.state.status(), ContainerState::Stopped);
    assert_eq!(service.kill(kill).await.expect("replay kill"), stopped);

    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(1_000),
    };
    let expected_exit = ExitStatus::signaled(15, false).expect("signal exit");
    assert_eq!(
        service.wait(wait.clone()).await.expect("wait for init"),
        expected_exit
    );
    assert_eq!(
        service.wait(wait).await.expect("repeat wait for init"),
        expected_exit
    );

    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("delete-1")),
        target,
        mode: DeleteMode::StoppedOnly,
    };
    service.delete(delete.clone()).await.expect("delete");
    service.delete(delete).await.expect("replay delete");

    let calls = driver.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Start(_)))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Kill(_)))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Delete(_)))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Wait(_)))
            .count(),
        1
    );
    let DriverCall::Create(driver_create) = &calls[0] else {
        panic!("create must be the first driver call");
    };
    assert_eq!(driver_create.bundle.config_json(), TEST_CONFIG);
    assert_eq!(driver_create.target.generation, Some(Generation(1)));

    let error = service
        .state(StateRequest {
            target: ContainerTarget::current(create.id),
        })
        .await
        .expect_err("deleted state must not remain visible");
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn control_plane_operations_are_durable_and_processes_are_exact() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_control_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let info = service.features().await.expect("configured features");
    for operation in [
        RuntimeOperation::Exec,
        RuntimeOperation::Pause,
        RuntimeOperation::Resume,
        RuntimeOperation::Processes,
    ] {
        assert!(
            info.operations.contains(&operation),
            "missing {operation:?}"
        );
    }

    let create = create_request(&bundle_directory, "control-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("control-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    let worker = service
        .exec(exec_request(
            target.clone(),
            "control-exec",
            "control-worker",
        ))
        .await
        .expect("exec worker");

    let processes = service
        .processes(ProcessesRequest {
            target: target.clone(),
        })
        .await
        .expect("list processes");
    assert_eq!(processes.len(), 2);
    assert!(processes
        .iter()
        .any(|process| process.target.process_id.is_init() && process.pid == Some(4_242)));
    assert!(processes.iter().any(|process| process == &worker));

    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("control-pause")),
        target: target.clone(),
    };
    let paused = service.pause(pause.clone()).await.expect("pause");
    assert!(paused.is_paused());
    assert_eq!(
        service.pause(pause).await.expect("replay pause"),
        paused,
        "pause replay must return the durable result"
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Pause(_)))
            .count(),
        1,
        "pause replay must not repeat the driver call"
    );

    let error = service
        .exec(exec_request(
            target.clone(),
            "control-exec-paused",
            "blocked-worker",
        ))
        .await
        .expect_err("exec while paused must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Exec(_)))
            .count(),
        1,
        "rejected exec must not reach the driver"
    );

    let resume = ContainerOperationRequest {
        context: OperationContext::new(operation_id("control-resume")),
        target: target.clone(),
    };
    let running = service.resume(resume.clone()).await.expect("resume");
    assert!(!running.is_paused());
    assert_eq!(
        service.resume(resume).await.expect("replay resume"),
        running,
        "resume replay must return the durable result"
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Resume(_)))
            .count(),
        1,
        "resume replay must not repeat the driver call"
    );
}

#[tokio::test]
async fn wait_is_exposed_only_when_the_driver_advertises_it() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let driver = Arc::new(RecordingDriver::without_wait());
    let service = open_service(&temporary, driver).await;
    let info = service.features().await.expect("configured features");
    assert!(!info.operations.contains(&RuntimeOperation::Wait));

    let error = service
        .wait(WaitRequest {
            target: ContainerTarget::current(container_id("missing")),
            timeout_ms: Some(0),
        })
        .await
        .expect_err("unadvertised wait must fail before state lookup");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(error.operation.as_deref(), Some("wait"));
}

#[tokio::test]
async fn terminal_driver_failures_replay_and_release_container_claims() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create_failure =
        Error::new(ErrorCode::FailedPrecondition, "guest rejected create").for_operation("create");
    driver.fail_next("create", create_failure.clone());
    let failed_create = create_request(&bundle_directory, "create-failed");

    assert_eq!(
        service
            .create(failed_create.clone())
            .await
            .expect_err("create must fail"),
        create_failure
    );
    assert_eq!(
        service
            .create(failed_create.clone())
            .await
            .expect_err("failed create must replay"),
        create_failure
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );

    let create = create_request(&bundle_directory, "create-retry-new-operation");
    let created = service
        .create(create.clone())
        .await
        .expect("container ID can be reused after failed create");
    assert_eq!(created.generation, Generation(2));
    assert_eq!(
        service
            .create(failed_create)
            .await
            .expect_err("old failed operation still replays after ID reuse"),
        create_failure
    );

    let target = ContainerTarget::exact(create.id, created.generation);
    let start_failure =
        Error::new(ErrorCode::Internal, "terminal start failure").for_operation("start");
    driver.fail_next("start", start_failure.clone());
    let failed_start = StartRequest {
        context: OperationContext::new(operation_id("start-failed")),
        target: target.clone(),
    };
    assert_eq!(
        service
            .start(failed_start.clone())
            .await
            .expect_err("start must fail"),
        start_failure
    );
    assert_eq!(
        service
            .start(failed_start)
            .await
            .expect_err("failed start must replay"),
        start_failure
    );

    let running = service
        .start(StartRequest {
            context: OperationContext::new(operation_id("start-after-failure")),
            target,
        })
        .await
        .expect("a new start can proceed after terminal failure");
    assert_eq!(*running.state.status(), ContainerState::Running);
}

#[tokio::test]
async fn retryable_driver_failure_keeps_the_same_operation_resumable() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    driver.fail_next(
        "create",
        Error::new(ErrorCode::Unavailable, "guest is booting")
            .for_operation("create")
            .retryable(true),
    );
    let request = create_request(&bundle_directory, "create-retryable");

    let error = service
        .create(request.clone())
        .await
        .expect_err("first create attempt must be retryable");
    assert!(error.retryable);
    let created = service
        .create(request)
        .await
        .expect("same operation resumes");
    assert_eq!(*created.state.status(), ContainerState::Created);
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        2
    );
}

#[tokio::test]
async fn freezer_driver_failures_replay_or_resume_according_to_retryability() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_control_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "freezer-failure-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id, created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("freezer-failure-start")),
            target: target.clone(),
        })
        .await
        .expect("start");

    let terminal_pause =
        Error::new(ErrorCode::Internal, "terminal pause failure").for_operation("pause");
    driver.fail_next("pause", terminal_pause.clone());
    let failed_pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("terminal-pause")),
        target: target.clone(),
    };
    assert_eq!(
        service
            .pause(failed_pause.clone())
            .await
            .expect_err("pause must fail"),
        terminal_pause
    );
    assert_eq!(
        service
            .pause(failed_pause)
            .await
            .expect_err("terminal pause must replay"),
        terminal_pause
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Pause(_)))
            .count(),
        1
    );

    let retryable_pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("retryable-pause")),
        target: target.clone(),
    };
    driver.fail_next(
        "pause",
        Error::new(ErrorCode::Unavailable, "freezer is busy")
            .for_operation("pause")
            .retryable(true),
    );
    assert!(
        service
            .pause(retryable_pause.clone())
            .await
            .expect_err("first pause attempt must be retryable")
            .retryable
    );
    assert!(service
        .pause(retryable_pause)
        .await
        .expect("same pause operation resumes")
        .is_paused());

    let terminal_resume =
        Error::new(ErrorCode::Internal, "terminal resume failure").for_operation("resume");
    driver.fail_next("resume", terminal_resume.clone());
    let failed_resume = ContainerOperationRequest {
        context: OperationContext::new(operation_id("terminal-resume")),
        target: target.clone(),
    };
    assert_eq!(
        service
            .resume(failed_resume.clone())
            .await
            .expect_err("resume must fail"),
        terminal_resume
    );
    assert_eq!(
        service
            .resume(failed_resume)
            .await
            .expect_err("terminal resume must replay"),
        terminal_resume
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Resume(_)))
            .count(),
        1
    );

    let retryable_resume = ContainerOperationRequest {
        context: OperationContext::new(operation_id("retryable-resume")),
        target,
    };
    driver.fail_next(
        "resume",
        Error::new(ErrorCode::Unavailable, "thaw is busy")
            .for_operation("resume")
            .retryable(true),
    );
    assert!(
        service
            .resume(retryable_resume.clone())
            .await
            .expect_err("first resume attempt must be retryable")
            .retryable
    );
    assert!(!service
        .resume(retryable_resume)
        .await
        .expect("same resume operation resumes")
        .is_paused());
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Pause(_)))
            .count(),
        3,
        "terminal pause calls once and retryable pause calls twice"
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Resume(_)))
            .count(),
        3,
        "terminal resume calls once and retryable resume calls twice"
    );
}

#[tokio::test]
async fn launch_and_isolation_checks_fail_before_state_or_driver_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("probe-only-state");
    let error = HostRuntimeService::open(&root, Arc::new(RecordingDriver::probe_only()))
        .await
        .expect_err("probe-only drivers cannot open lifecycle state");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(!root.exists());

    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = HostRuntimeService::open(
        temporary.path().join("supported-state"),
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open supported driver");
    let mut request = create_request(&bundle_directory, "unsupported-isolation");
    request.isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: identifier("test-domain", TrustDomainId::new),
    };
    let error = service
        .create(request)
        .await
        .expect_err("unsupported isolation must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(driver.calls().is_empty());
}
