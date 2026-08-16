use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixListener;

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::{
    Arch, ContainerState, LinuxNamespaceType, LinuxResources, LinuxSeccompAction, Process,
};
use a3s_oci_sdk::{
    async_trait, CloseStdinRequest, ContainerId, ContainerOperationRequest, ContainerRecord,
    ContainerStats, ContainerTarget, CpuStats, CreateAttachments, CreateRequest, DeleteMode,
    DeleteRequest, Error, ErrorCode, EventsRequest, ExecRequest, ExitStatus, FileOp, FileRequest,
    FileResponse, FilesystemEntry, FilesystemEntryKind, FilesystemOp, FilesystemRequest,
    FilesystemResponse, Generation, IoMode, IsolationRequest, KillRequest, ListRequest,
    MemoryStats, OciBundle, OciRuntimeService, OciSchemaValidator, OperationContext, OperationId,
    OutputChunk, OutputStream, ProcessId, ProcessIo, ProcessRecord, ProcessTarget,
    ProcessesRequest, ReadOutputRequest, ResizeRequest, Result, RuntimeEventKind, RuntimeOperation,
    Signal, SignalProcessRequest, StartRequest, StateRequest, StatsRequest, TerminalSize,
    TrustDomainId, UpdateRequest, WaitProcessRequest, WaitRequest, WriteStdinRequest,
    ATTACHMENT_SCHEMA_V1, OCI_LINUX_CAPABILITY_NAMES, OCI_LINUX_MEMORY_POLICY_FLAGS,
    OCI_LINUX_MEMORY_POLICY_MODES, OCI_LINUX_MOUNT_OPTIONS,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::HostRuntimeService;
#[cfg(target_os = "linux")]
use crate::DriverCreateAttachments;
use crate::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverRecovery, DriverResizeRequest, DriverSignalProcessRequest,
    DriverStartRequest, DriverState, DriverUpdateRequest, DriverWaitProcessRequest,
    DriverWaitRequest, DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

mod agent_transport_recovery;
mod fault_matrix;
mod filesystem_operations;
mod io_durability;
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
    Recover(ContainerRecord),
    Create(Box<DriverCreateRequest>),
    State(ContainerTarget),
    Start(Box<DriverStartRequest>),
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
    CloseStdin(DriverCloseStdinRequest),
    Resize(DriverResizeRequest),
    File(FileRequest),
    Filesystem(FilesystemRequest),
}

type DriverProcessKey = (ContainerId, Generation, ProcessId);
type DriverProcessState = (DriverProcess, Option<ExitStatus>);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DurableProcessFixture {
    target: ProcessTarget,
    pid: i32,
    terminal: bool,
    exit_status: Option<ExitStatus>,
}

#[derive(Debug)]
struct RecordingDriver {
    capability: DriverCapability,
    operations: Vec<RuntimeOperation>,
    hooks: Vec<OciHookPhase>,
    calls: Mutex<Vec<DriverCall>>,
    acknowledgements: Mutex<Vec<OperationId>>,
    states: Mutex<HashMap<ContainerId, (Generation, DriverState)>>,
    exits: Mutex<HashMap<ContainerId, ExitStatus>>,
    processes: Mutex<HashMap<DriverProcessKey, DriverProcessState>>,
    exec_replays: Mutex<HashMap<OperationId, (DriverExecRequest, DriverProcess)>>,
    signal_process_replays: Mutex<HashMap<OperationId, DriverSignalProcessRequest>>,
    update_replays: Mutex<HashMap<OperationId, DriverUpdateRequest>>,
    write_stdin_replays: Mutex<HashMap<OperationId, DriverWriteStdinRequest>>,
    close_stdin_replays: Mutex<HashMap<OperationId, DriverCloseStdinRequest>>,
    resize_replays: Mutex<HashMap<OperationId, DriverResizeRequest>>,
    output_responses: Mutex<VecDeque<Vec<OutputChunk>>>,
    recovery: Mutex<DriverRecovery>,
    failures: Mutex<HashMap<&'static str, Vec<Error>>>,
    process_fixture_log: Option<PathBuf>,
    process_fixture_state: Option<PathBuf>,
    recover_process_fixture_state: bool,
    staged_bundle_directory: Option<PathBuf>,
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
            hooks: Vec::new(),
            calls: Mutex::new(Vec::new()),
            acknowledgements: Mutex::new(Vec::new()),
            states: Mutex::new(HashMap::new()),
            exits: Mutex::new(HashMap::new()),
            processes: Mutex::new(HashMap::new()),
            exec_replays: Mutex::new(HashMap::new()),
            signal_process_replays: Mutex::new(HashMap::new()),
            update_replays: Mutex::new(HashMap::new()),
            write_stdin_replays: Mutex::new(HashMap::new()),
            close_stdin_replays: Mutex::new(HashMap::new()),
            resize_replays: Mutex::new(HashMap::new()),
            output_responses: Mutex::new(VecDeque::new()),
            recovery: Mutex::new(DriverRecovery::none()),
            failures: Mutex::new(HashMap::new()),
            process_fixture_log: None,
            process_fixture_state: None,
            recover_process_fixture_state: false,
            staged_bundle_directory: None,
        }
    }

    fn process_fixture(log: PathBuf) -> Self {
        let state = log.with_extension("processes.json");
        let mut driver = Self::with_control_operations();
        driver.capability.evidence =
            BTreeMap::from([("test-driver".to_string(), "out-of-process".to_string())]);
        driver.process_fixture_log = Some(log);
        driver.process_fixture_state = Some(state);
        driver.recover_process_fixture_state = true;
        driver
    }

    fn probe_only() -> Self {
        let mut driver = Self::supported();
        driver.capability.readiness = DriverReadiness::ProbeOnly;
        driver
    }

    fn shared_guest_supported() -> Self {
        let mut driver = Self::supported();
        driver.capability.driver = DriverKind::LibkrunHvf;
        driver.capability.isolation_classes = vec![IsolationClass::SharedGuestKernel];
        driver
    }

    #[cfg(target_os = "linux")]
    fn native_supported() -> Self {
        let mut driver = Self::supported();
        driver.capability.driver = DriverKind::NativeLinux;
        driver.capability.isolation_classes = vec![IsolationClass::SharedHostKernel];
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
            RuntimeOperation::Resize,
            RuntimeOperation::File,
            RuntimeOperation::Filesystem,
        ]);
        driver
    }

    fn with_hooks(hooks: Vec<OciHookPhase>) -> Self {
        let mut driver = Self::supported();
        driver.hooks = hooks;
        driver
    }

    fn with_staged_bundle(directory: PathBuf) -> Self {
        let mut driver = Self::supported();
        driver.staged_bundle_directory = Some(directory);
        driver
    }

    fn calls(&self) -> Vec<DriverCall> {
        self.calls.lock().expect("driver calls lock").clone()
    }

    fn acknowledgements(&self) -> Vec<OperationId> {
        self.acknowledgements
            .lock()
            .expect("driver acknowledgements lock")
            .clone()
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

    fn set_recovery_observation(&self, observation: DriverState) {
        *self.recovery.lock().expect("driver recovery lock") =
            DriverRecovery::observed(observation);
    }

    fn set_recreated_created_recovery(&self, observation: DriverState) {
        *self.recovery.lock().expect("driver recovery lock") =
            DriverRecovery::recreated_created(observation)
                .expect("valid recreated created recovery");
    }

    fn set_recreated_running_recovery(&self, observation: DriverState) {
        *self.recovery.lock().expect("driver recovery lock") =
            DriverRecovery::recreated_running(observation)
                .expect("valid recreated running recovery");
    }

    fn set_recreated_running_recovery_with_processes(
        &self,
        observation: DriverState,
        processes: Vec<ProcessRecord>,
    ) {
        *self.recovery.lock().expect("driver recovery lock") =
            DriverRecovery::recreated_running_with_processes(observation, processes)
                .expect("valid recreated running process recovery");
    }

    fn set_recovery_exit(&self, status: ExitStatus) {
        *self.recovery.lock().expect("driver recovery lock") =
            DriverRecovery::stopped_with_exit(status).expect("valid recovery exit status");
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

    fn record_process_fixture_call(&self, operation: &'static str) -> Result<()> {
        let Some(path) = &self.process_fixture_log else {
            return Ok(());
        };
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| {
                Error::new(
                    ErrorCode::Internal,
                    format!(
                        "failed to open out-of-process driver log {}: {error}",
                        path.display()
                    ),
                )
                .for_operation("record-process-fixture-call")
            })?;
        writeln!(log, "{operation}").map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to append out-of-process driver log {}: {error}",
                    path.display()
                ),
            )
            .for_operation("record-process-fixture-call")
        })
    }

    fn load_process_fixture_state(&self) -> Result<Vec<DurableProcessFixture>> {
        let Some(path) = &self.process_fixture_state else {
            return Ok(Vec::new());
        };
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "failed to read out-of-process driver state {}: {error}",
                        path.display()
                    ),
                )
                .for_operation("load-process-fixture-state"))
            }
        };
        serde_json::from_slice(&bytes).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to decode out-of-process driver state {}: {error}",
                    path.display()
                ),
            )
            .for_operation("load-process-fixture-state")
        })
    }

    fn store_process_fixture_state(&self) -> Result<()> {
        let Some(path) = &self.process_fixture_state else {
            return Ok(());
        };
        let processes = self.processes.lock().expect("driver processes lock");
        let mut durable: Vec<_> = processes
            .iter()
            .map(
                |((container_id, generation, process_id), (process, exit_status))| {
                    DurableProcessFixture {
                        target: ProcessTarget {
                            container: ContainerTarget::exact(container_id.clone(), *generation),
                            process_id: process_id.clone(),
                        },
                        pid: process.pid(),
                        terminal: process.terminal(),
                        exit_status: exit_status.clone(),
                    }
                },
            )
            .collect();
        drop(processes);
        durable.sort_by(|left, right| {
            left.target
                .container
                .id
                .as_str()
                .cmp(right.target.container.id.as_str())
                .then_with(|| {
                    left.target
                        .process_id
                        .as_str()
                        .cmp(right.target.process_id.as_str())
                })
        });
        let bytes = serde_json::to_vec(&durable).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to encode out-of-process driver state: {error}"),
            )
            .for_operation("store-process-fixture-state")
        })?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                Error::new(
                    ErrorCode::Internal,
                    format!(
                        "failed to open out-of-process driver state {}: {error}",
                        path.display()
                    ),
                )
                .for_operation("store-process-fixture-state")
            })?;
        file.write_all(&bytes).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to write out-of-process driver state {}: {error}",
                    path.display()
                ),
            )
            .for_operation("store-process-fixture-state")
        })?;
        file.sync_all().map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to sync out-of-process driver state {}: {error}",
                    path.display()
                ),
            )
            .for_operation("store-process-fixture-state")
        })
    }

    fn recover_process_fixture(&self, record: &ContainerRecord) -> Result<()> {
        let status = record.state.status();
        let state = if status == &ContainerState::Stopped {
            DriverState::stopped()
        } else {
            let pid = (*record.state.pid()).ok_or_else(|| {
                Error::new(
                    ErrorCode::FailedPrecondition,
                    "live process fixture record has no init PID",
                )
                .for_operation("recover-process-fixture")
            })?;
            if status == &ContainerState::Created {
                DriverState::created(pid)?
            } else if status == &ContainerState::Running {
                DriverState::running(pid)?.with_paused(record.is_paused())?
            } else {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    format!("process fixture cannot recover OCI state {status}"),
                )
                .for_operation("recover-process-fixture"));
            }
        };
        self.states
            .lock()
            .expect("driver states lock")
            .insert(container_id(record.state.id()), (record.generation, state));
        let restored = self.load_process_fixture_state()?;
        let mut processes = self.processes.lock().expect("driver processes lock");
        for process in restored {
            if process.target.container.id.as_str() != record.state.id()
                || process.target.container.generation != Some(record.generation)
            {
                continue;
            }
            let key = Self::process_key(&process.target)?;
            processes.insert(
                key,
                (
                    DriverProcess::new(process.pid, process.terminal)?,
                    process.exit_status,
                ),
            );
        }
        Ok(())
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

    fn hooks(&self) -> &[OciHookPhase] {
        &self.hooks
    }

    async fn acknowledge_operation(&self, operation_id: &OperationId) -> Result<()> {
        self.acknowledgements
            .lock()
            .expect("driver acknowledgements lock")
            .push(operation_id.clone());
        Ok(())
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<DriverRecovery> {
        if self.recover_process_fixture_state {
            self.record_process_fixture_call("recover")?;
            self.recover_process_fixture(record)?;
            return Ok(DriverRecovery::none());
        }
        let recovery = self.recovery.lock().expect("driver recovery lock").clone();
        if recovery != DriverRecovery::none() {
            self.calls
                .lock()
                .expect("driver calls lock")
                .push(DriverCall::Recover(record.clone()));
        }
        Ok(recovery)
    }

    async fn prepare_create_bundle(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        self.staged_bundle_directory.as_ref().map_or_else(
            || Ok(request.bundle.clone()),
            |directory| {
                OciBundle::from_json(directory.clone(), request.bundle.config_json().to_string())
            },
        )
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.record_process_fixture_call("create")?;
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Create(Box::new(request.clone())));
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
        self.record_process_fixture_call("start")?;
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Start(Box::new(request.clone())));
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
        self.record_process_fixture_call("kill")?;
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
        self.record_process_fixture_call("delete")?;
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
        self.store_process_fixture_state()?;
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
        self.record_process_fixture_call("exec")?;
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
        drop(processes);
        self.store_process_fixture_state()?;
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
        drop(processes);
        self.record_process_fixture_call("signal-process")?;
        self.store_process_fixture_state()?;
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
        self.record_process_fixture_call("read-output")?;
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::ReadOutput(request.clone()));
        if let Some(error) = self.take_failure("read-output") {
            return Err(error);
        }
        if self.process_fixture_state.is_some() {
            let key = Self::process_key(&request.target)?;
            let processes = self.processes.lock().expect("driver processes lock");
            let (process, exit_status) = processes.get(&key).ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "driver process does not exist")
                    .for_operation("driver-read-output")
            })?;
            let data = b"runtime owner process\n".to_vec();
            let data_sequence = u64::try_from(data.len()).expect("fixture output length");
            let mut chunks = vec![OutputChunk {
                sequence: data_sequence,
                stream: OutputStream::Stdout,
                data,
                eof: false,
            }];
            if exit_status.is_some() {
                chunks.push(OutputChunk {
                    sequence: data_sequence + 1,
                    stream: OutputStream::Stdout,
                    data: Vec::new(),
                    eof: true,
                });
                if !process.terminal() {
                    chunks.push(OutputChunk {
                        sequence: data_sequence + 2,
                        stream: OutputStream::Stderr,
                        data: Vec::new(),
                        eof: true,
                    });
                }
            }
            drop(processes);
            let mut bytes = 0_u64;
            return Ok(chunks
                .into_iter()
                .filter(|chunk| chunk.sequence > request.after_sequence)
                .take_while(|chunk| {
                    let next = bytes.saturating_add(chunk.data.len() as u64);
                    if next > u64::from(request.max_bytes) {
                        false
                    } else {
                        bytes = next;
                        true
                    }
                })
                .collect());
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
        self.record_process_fixture_call("write-stdin")?;
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::WriteStdin(request.clone()));
        if let Some(recorded) = self
            .write_stdin_replays
            .lock()
            .expect("driver write-stdin replay lock")
            .get(&request.context.operation_id)
        {
            if recorded != &request {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    "driver write-stdin operation ID was reused for a different request",
                )
                .for_operation("driver-write-stdin"));
            }
            return Ok(());
        }
        if let Some(error) = self.take_failure("write-stdin") {
            return Err(error);
        }
        self.write_stdin_replays
            .lock()
            .expect("driver write-stdin replay lock")
            .insert(request.context.operation_id.clone(), request);
        Ok(())
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::CloseStdin(request.clone()));
        if let Some(recorded) = self
            .close_stdin_replays
            .lock()
            .expect("driver close-stdin replay lock")
            .get(&request.context.operation_id)
        {
            if recorded != &request {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    "driver close-stdin operation ID was reused for a different request",
                )
                .for_operation("driver-close-stdin"));
            }
            return Ok(());
        }
        if let Some(error) = self.take_failure("close-stdin") {
            return Err(error);
        }
        self.close_stdin_replays
            .lock()
            .expect("driver close-stdin replay lock")
            .insert(request.context.operation_id.clone(), request);
        Ok(())
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Resize(request.clone()));
        if let Some(recorded) = self
            .resize_replays
            .lock()
            .expect("driver resize replay lock")
            .get(&request.context.operation_id)
        {
            if recorded != &request {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    "driver resize operation ID was reused for a different request",
                )
                .for_operation("driver-resize"));
            }
            return Ok(());
        }
        if let Some(error) = self.take_failure("resize") {
            return Err(error);
        }
        self.resize_replays
            .lock()
            .expect("driver resize replay lock")
            .insert(request.context.operation_id.clone(), request);
        Ok(())
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::File(request.clone()));
        if let Some(error) = self.take_failure("file") {
            return Err(error);
        }
        let (data, size) = match request.op {
            FileOp::Upload => {
                let decoded = STANDARD
                    .decode(request.data.as_deref().unwrap_or_default())
                    .map_err(|error| {
                        Error::new(ErrorCode::InvalidArgument, error.to_string())
                            .for_operation("driver-file")
                    })?;
                (None, decoded.len() as u64)
            }
            FileOp::Download => (Some(String::new()), 0),
        };
        Ok(FileResponse {
            target: request.target,
            data,
            size,
        })
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Filesystem(request.clone()));
        if let Some(error) = self.take_failure("filesystem") {
            return Err(error);
        }
        let entry = matches!(
            request.op,
            FilesystemOp::Stat | FilesystemOp::MakeDir | FilesystemOp::Move
        )
        .then(|| FilesystemEntry {
            name: "fixture".to_string(),
            kind: FilesystemEntryKind::File,
            path: request
                .destination
                .clone()
                .unwrap_or_else(|| request.path.clone()),
            size: 0,
            mode: 0o644,
            permissions: "-rw-r--r--".to_string(),
            owner: "root".to_string(),
            group: "root".to_string(),
            modified_seconds: 0,
            modified_nanos: 0,
            symlink_target: None,
            metadata: BTreeMap::new(),
        });
        Ok(FilesystemResponse {
            target: request.target,
            entry,
            entries: Vec::new(),
        })
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
    let bundle = OciBundle::from_json(bundle_directory.to_path_buf(), TEST_CONFIG)
        .expect("valid OCI bundle");
    CreateRequest {
        context: OperationContext::new(operation_id(operation)),
        id: container_id("sdk-container"),
        attachments: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("valid attachment contract"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
    }
}

#[cfg(target_os = "linux")]
fn native_create_request(bundle_directory: &Path, operation: &str) -> CreateRequest {
    let mut request = create_request(bundle_directory, operation);
    request.isolation = IsolationRequest::SharedHostKernel;
    request
}

#[cfg(target_os = "linux")]
fn native_control_descriptors(directory: &Path, name: &str) -> crate::NativeControlDescriptors {
    std::fs::create_dir_all(directory).expect("control descriptor directory");
    let exec =
        UnixListener::bind(directory.join(format!("{name}-exec.sock"))).expect("exec listener");
    let pty = UnixListener::bind(directory.join(format!("{name}-pty.sock"))).expect("PTY listener");
    let log = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(format!("{name}-init.log")))
        .expect("init log");
    crate::NativeControlDescriptors::new(exec, pty, log).expect("native control descriptors")
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
    assert!(info.attachments.supports_schema(ATTACHMENT_SCHEMA_V1));
    assert_eq!(info.oci.oci_version_min(), "1.0.0");
    assert_eq!(info.oci.oci_version_max(), "1.3.0");
    assert_eq!(info.oci.hooks().as_deref(), Some([].as_slice()));
    let mount_options = info
        .oci
        .mount_options()
        .as_deref()
        .expect("Linux mount options");
    assert_eq!(mount_options.len(), OCI_LINUX_MOUNT_OPTIONS.len());
    assert!(mount_options.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(!mount_options.iter().any(|option| option == "tmpcopyup"));
    assert!(mount_options.iter().any(|option| option == "rnodev"));
    for option in OCI_LINUX_MOUNT_OPTIONS
        .iter()
        .map(|option| option.name())
        .filter(|option| *option != "tmpcopyup")
    {
        assert!(
            mount_options.iter().any(|reported| reported == option),
            "supported OCI mount option `{option}` is not advertised"
        );
    }
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
            OCI_LINUX_CAPABILITY_NAMES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    let cgroup = linux.cgroup().as_ref().expect("cgroup feature report");
    assert_eq!(*cgroup.v1(), Some(false));
    assert_eq!(*cgroup.v2(), Some(true));
    let apparmor = linux.apparmor().as_ref().expect("apparmor feature report");
    assert_eq!(*apparmor.enabled(), Some(false));
    let selinux = linux.selinux().as_ref().expect("selinux feature report");
    assert_eq!(*selinux.enabled(), Some(false));
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
    let memory_policy = linux
        .memory_policy()
        .as_ref()
        .expect("memory-policy feature report");
    assert_eq!(
        memory_policy.modes().as_deref(),
        Some(
            OCI_LINUX_MEMORY_POLICY_MODES
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    assert_eq!(
        memory_policy.flags().as_deref(),
        Some(
            OCI_LINUX_MEMORY_POLICY_FLAGS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
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
async fn reports_driver_hook_phases_in_normative_order_and_rejects_duplicates() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let driver = Arc::new(RecordingDriver::with_hooks(vec![
        OciHookPhase::Poststop,
        OciHookPhase::CreateContainer,
        OciHookPhase::Prestart,
        OciHookPhase::Poststart,
        OciHookPhase::StartContainer,
        OciHookPhase::CreateRuntime,
    ]));
    let service = HostRuntimeService::open(temporary.path().join("state"), driver)
        .await
        .expect("open hook-capable runtime");
    let info = service.features().await.expect("hook feature report");
    assert_eq!(
        info.oci.hooks().as_deref(),
        Some(
            [
                "prestart",
                "createRuntime",
                "createContainer",
                "startContainer",
                "poststart",
                "poststop",
            ]
            .map(str::to_string)
            .as_slice()
        )
    );

    let duplicate_root = temporary.path().join("duplicate-state");
    let error = HostRuntimeService::open(
        &duplicate_root,
        Arc::new(RecordingDriver::with_hooks(vec![
            OciHookPhase::Poststop,
            OciHookPhase::Poststop,
        ])),
    )
    .await
    .expect_err("duplicate hook phases must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(!duplicate_root.exists());
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
async fn durable_list_is_sorted_filtered_driver_independent_and_reopen_safe() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let mut recording = RecordingDriver::supported();
    recording
        .capability
        .isolation_classes
        .push(IsolationClass::SharedGuestKernel);
    let driver = Arc::new(recording);
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let mut zulu = create_request(&bundle_directory, "list-create-zulu");
    zulu.id = container_id("list-zulu");
    service.create(zulu).await.expect("create zulu");
    let mut alpha = create_request(&bundle_directory, "list-create-alpha");
    alpha.id = container_id("list-alpha");
    alpha.isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: TrustDomainId::new("list-domain").expect("trust-domain ID"),
    };
    service.create(alpha).await.expect("create alpha");

    let driver_calls = driver.calls().len();
    let records = service
        .list(ListRequest::default())
        .await
        .expect("list all containers");
    assert_eq!(
        records
            .iter()
            .map(|record| record.state.id().as_str())
            .collect::<Vec<_>>(),
        ["list-alpha", "list-zulu"]
    );
    assert_eq!(driver.calls().len(), driver_calls, "list called the driver");

    let shared = service
        .list(ListRequest {
            isolation: Some(IsolationClass::SharedGuestKernel),
        })
        .await
        .expect("list shared-guest containers");
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].state.id(), "list-alpha");
    assert_eq!(shared[0].isolation, IsolationClass::SharedGuestKernel);

    drop(service);
    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    let replayed = reopened
        .list(ListRequest::default())
        .await
        .expect("list after service reopen");
    assert_eq!(replayed, records);
}

#[tokio::test]
async fn durable_list_fails_closed_on_an_invalid_container_entry() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, driver).await;
    let invalid = temporary.path().join("state/containers/not-a-directory");
    std::fs::write(&invalid, b"invalid").expect("write invalid container entry");

    let error = service
        .list(ListRequest::default())
        .await
        .expect_err("invalid state entry must fail list");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("not a plain directory"));
}

#[tokio::test]
async fn durable_events_are_host_owned_replay_safe_and_reopen_safe() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let create = create_request(&bundle_directory, "event-create");
    let created = service
        .create(create.clone())
        .await
        .expect("create container");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let request = EventsRequest {
        container: Some(target.clone()),
        after_sequence: 0,
        limit: 16,
        wait_timeout_ms: None,
    };
    let driver_calls = driver.calls().len();
    let events = service
        .events(request.clone())
        .await
        .expect("poll runtime events");
    assert_eq!(
        events
            .events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        [
            RuntimeEventKind::ContainerCreating,
            RuntimeEventKind::ContainerCreated,
        ]
    );
    assert_eq!(events.next_sequence, 2);
    assert_eq!(
        driver.calls().len(),
        driver_calls,
        "events called the driver"
    );

    assert_eq!(
        service.create(create.clone()).await.expect("replay create"),
        created
    );
    assert_eq!(
        service
            .events(request)
            .await
            .expect("poll after create replay"),
        events
    );

    let calls_before_invalid = driver.calls().len();
    let error = service
        .events(EventsRequest {
            container: None,
            after_sequence: 0,
            limit: 0,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("zero event limit must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(driver.calls().len(), calls_before_invalid);

    let waiting_service = service.clone();
    let second_target = ContainerTarget::current(container_id("event-second"));
    let waiter = tokio::spawn(async move {
        waiting_service
            .events(EventsRequest {
                container: Some(second_target),
                after_sequence: events.next_sequence,
                limit: 16,
                wait_timeout_ms: Some(2_000),
            })
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let mut second = create_request(&bundle_directory, "event-second-create");
    second.id = container_id("event-second");
    service
        .create(second)
        .await
        .expect("create second container");
    let awakened = waiter
        .await
        .expect("join event waiter")
        .expect("event waiter result");
    assert!(!awakened.events.is_empty());
    assert!(awakened
        .events
        .iter()
        .all(|event| event.container.id.as_str() == "event-second"));

    drop(service);
    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    let replayed = reopened
        .events(EventsRequest {
            container: Some(target),
            after_sequence: 0,
            limit: 16,
            wait_timeout_ms: None,
        })
        .await
        .expect("poll events after reopen");
    assert_eq!(replayed.events.len(), 2);
    assert_eq!(replayed.events[1].kind, RuntimeEventKind::ContainerCreated);
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
            RuntimeOperation::List,
            RuntimeOperation::Events,
        ]
    );

    let create = create_request(&bundle_directory, "create-1");
    let created = service.create(create.clone()).await.expect("create");
    assert_eq!(*created.state.status(), ContainerState::Created);
    assert_eq!(*created.state.pid(), Some(4_242));
    assert_eq!(created.generation, Generation(1));
    let expected_attachments_digest = create.attachments.digest().expect("attachment digest");
    assert_eq!(
        created.attachments_digest.as_deref(),
        Some(expected_attachments_digest.as_str())
    );
    assert_eq!(
        service.create(create.clone()).await.expect("replay create"),
        created
    );

    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let expected_target = target.clone();
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
    assert_eq!(
        driver.acknowledgements(),
        vec![
            operation_id("create-1"),
            operation_id("create-1"),
            operation_id("start-1"),
            operation_id("start-1"),
            operation_id("kill-1"),
            operation_id("kill-1"),
            operation_id("delete-1"),
            operation_id("delete-1"),
        ],
        "the driver must release replay records only after durable completion and on replay"
    );
    let DriverCall::Create(driver_create) = &calls[0] else {
        panic!("create must be the first driver call");
    };
    assert_eq!(driver_create.bundle.config_json(), TEST_CONFIG);
    assert_eq!(driver_create.target.generation, Some(Generation(1)));
    assert_eq!(driver_create.attachment_contract, create.attachments);

    let DriverCall::Start(driver_start) = calls
        .iter()
        .find(|call| matches!(call, DriverCall::Start(_)))
        .expect("exact driver start call")
    else {
        unreachable!("filtered driver call must be start");
    };
    assert_eq!(driver_start.target, expected_target);
    assert_eq!(
        driver_start
            .bundle
            .spec()
            .process()
            .as_ref()
            .expect("start process")
            .args()
            .as_deref(),
        Some(["/bin/true".to_string()].as_slice())
    );

    let DriverCall::Kill(driver_kill) = calls
        .iter()
        .find(|call| matches!(call, DriverCall::Kill(_)))
        .expect("exact driver kill call")
    else {
        unreachable!("filtered driver call must be kill");
    };
    assert_eq!(driver_kill.target, expected_target);
    assert_eq!(driver_kill.signal.get(), 15);
    assert!(driver_kill.all);

    let DriverCall::Delete(driver_delete) = calls
        .iter()
        .find(|call| matches!(call, DriverCall::Delete(_)))
        .expect("exact driver delete call")
    else {
        unreachable!("filtered driver call must be delete");
    };
    assert_eq!(driver_delete.target, expected_target);
    assert_eq!(driver_delete.mode, DeleteMode::StoppedOnly);

    let error = service
        .state(StateRequest {
            target: ContainerTarget::current(create.id),
        })
        .await
        .expect_err("deleted state must not remain visible");
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn source_config_updates_after_create_do_not_affect_start() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let source_config = bundle_directory.join("config.json");
    std::fs::write(&source_config, TEST_CONFIG).expect("write source configuration");
    let bundle = OciBundle::load(&bundle_directory)
        .await
        .expect("load source bundle");
    let original_digest = bundle.config_digest().to_string();
    let create = CreateRequest {
        context: OperationContext::new(operation_id("immutable-config-create")),
        id: container_id("immutable-config-container"),
        attachments: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("attachment contract"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
    };
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let created = service
        .create(create.clone())
        .await
        .expect("create container");

    let mut changed: serde_json::Value =
        serde_json::from_str(TEST_CONFIG).expect("decode source configuration");
    changed["process"]["args"] = serde_json::json!(["/bin/false"]);
    std::fs::write(
        &source_config,
        serde_json::to_vec_pretty(&changed).expect("encode changed source configuration"),
    )
    .expect("change source configuration after create");

    drop(service);
    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    let target = ContainerTarget::exact(create.id, created.generation);
    reopened
        .start(StartRequest {
            context: OperationContext::new(operation_id("immutable-config-start")),
            target,
        })
        .await
        .expect("start from durable configuration snapshot");

    let calls = driver.calls();
    let DriverCall::Start(start) = calls
        .iter()
        .find(|call| matches!(call, DriverCall::Start(_)))
        .expect("driver start call")
    else {
        unreachable!("filtered driver call must be start");
    };
    assert_eq!(start.bundle.config_json(), TEST_CONFIG);
    assert_eq!(start.bundle.config_digest(), original_digest);
    assert_ne!(
        start.bundle.config_bytes(),
        std::fs::read(&source_config)
            .expect("read changed source configuration")
            .as_slice()
    );
}

#[tokio::test]
async fn create_uses_driver_staged_bundle_without_rewriting_public_bundle_identity() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let source = temporary.path().join("caller-bundle");
    let staged = temporary.path().join("runtime-generation/bundle");
    std::fs::create_dir(&source).expect("source bundle directory");
    let driver = Arc::new(RecordingDriver::with_staged_bundle(staged.clone()));
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&source, "staged-create");

    let created = service.create(create.clone()).await.expect("staged create");
    assert_eq!(created.state.bundle(), &source);
    let calls = driver.calls();
    let DriverCall::Create(driver_create) = calls
        .iter()
        .find(|call| matches!(call, DriverCall::Create(_)))
        .expect("driver create call")
    else {
        unreachable!("filtered driver call must be create");
    };
    assert_eq!(driver_create.bundle.directory(), staged);
    assert_eq!(
        driver_create.bundle.config_digest(),
        create.bundle.config_digest()
    );
    assert_eq!(driver_create.attachment_contract, create.attachments);

    assert_eq!(
        service
            .create(create)
            .await
            .expect("replayed staged create"),
        created
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );
}

#[tokio::test]
async fn required_runtime_extension_fails_before_durable_or_driver_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("extension-bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let bundle = OciBundle::from_json(
        bundle_directory,
        concat!(
            "{\n",
            "  \"ociVersion\": \"1.3.0\",\n",
            "  \"process\": {\"terminal\": false, \"user\": {\"uid\": 0, \"gid\": 0}, \"args\": [\"/bin/true\"], \"cwd\": \"/\"},\n",
            "  \"root\": {\"path\": \"rootfs\", \"readonly\": true},\n",
            "  \"annotations\": {\"dev.a3s.network.tsi\": \"proxy-v1\"}\n",
            "}\n"
        ),
    )
    .expect("extension bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .add_extension_from_annotation(&bundle, "dev.a3s.network.tsi", 1, true)
        .expect("required extension declaration")
        .attach_network_extension("dev.a3s.network.tsi")
        .expect("network extension classification");
    let request = CreateRequest {
        context: OperationContext::new(operation_id("required-extension-create")),
        id: container_id("required-extension-container"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments,
    };

    let error = service
        .create(request.clone())
        .await
        .expect_err("unsupported required extension must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("dev.a3s.network.tsi"));
    assert!(driver.calls().is_empty());
    assert!(!temporary
        .path()
        .join("state/containers")
        .join(request.id.as_str())
        .exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_control_create_is_forwarded_durable_and_reopened_by_logical_schema() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::native_supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = native_create_request(&bundle_directory, "native-control-create");
    let descriptors = native_control_descriptors(&temporary.path().join("control"), "first");

    let created = service
        .create_with_native_control_descriptors(create.clone(), descriptors.clone())
        .await
        .expect("native control create");
    assert_eq!(
        service
            .create_with_native_control_descriptors(create.clone(), descriptors)
            .await
            .expect("replay native control create"),
        created
    );
    let calls = driver.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );
    let DriverCall::Create(driver_create) = calls
        .iter()
        .find(|call| matches!(call, DriverCall::Create(_)))
        .expect("driver create call")
    else {
        unreachable!("matched create call")
    };
    assert!(matches!(
        driver_create.attachments,
        DriverCreateAttachments::NativeControl(_)
    ));

    let error = service
        .create(create.clone())
        .await
        .expect_err("retry without native descriptors must conflict");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    drop(service);

    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    let reopened_descriptors =
        native_control_descriptors(&temporary.path().join("control"), "reopened");
    assert_eq!(
        reopened
            .create_with_native_control_descriptors(create, reopened_descriptors)
            .await
            .expect("replay with reopened equivalent resources"),
        created
    );
    assert_eq!(driver.calls(), calls);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn bound_native_control_service_routes_transport_style_create_to_one_container() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::native_supported());
    let create = native_create_request(&bundle_directory, "bound-native-control");
    let descriptors = native_control_descriptors(&temporary.path().join("control"), "bound");
    let service = HostRuntimeService::open_with_native_control_descriptors(
        temporary.path().join("state"),
        driver.clone(),
        create.id.clone(),
        descriptors,
    )
    .await
    .expect("open bound native control service");

    service
        .create(create.clone())
        .await
        .expect("normal service create must carry the bound descriptors");
    let calls = driver.calls();
    let DriverCall::Create(driver_create) = calls
        .iter()
        .find(|call| matches!(call, DriverCall::Create(_)))
        .expect("driver create call")
    else {
        unreachable!("matched create call")
    };
    assert!(matches!(
        driver_create.attachments,
        DriverCreateAttachments::NativeControl(_)
    ));

    let other_bundle = temporary.path().join("other-bundle");
    std::fs::create_dir(&other_bundle).expect("other bundle directory");
    let mut other = native_create_request(&other_bundle, "other-container-create");
    other.id = container_id("other-container");
    let error = service
        .create(other)
        .await
        .expect_err("a bound service must not reuse control descriptors for another container");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(error.message.contains("sdk-container"));
    assert!(error.message.contains("other-container"));
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn non_native_driver_rejects_control_descriptors_without_claiming_operation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "non-native-control-create");
    let descriptors = native_control_descriptors(&temporary.path().join("control"), "rejected");

    let error = service
        .create_with_native_control_descriptors(create.clone(), descriptors)
        .await
        .expect_err("non-native driver must reject control descriptors");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("does not accept"));
    assert!(driver.calls().is_empty());

    service
        .create(create)
        .await
        .expect("rejected attachment must not claim operation ID");
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );
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

#[tokio::test]
async fn multi_driver_service_routes_create_and_reopen_by_durable_driver() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("multi-driver-state");
    let dedicated = Arc::new(RecordingDriver::supported());
    let shared = Arc::new(RecordingDriver::shared_guest_supported());
    let drivers: Vec<Arc<dyn RuntimeDriver>> = vec![dedicated.clone(), shared.clone()];
    let service = HostRuntimeService::open_with_drivers(&state_root, drivers)
        .await
        .expect("open multi-driver service");

    let mut dedicated_request = create_request(&bundle_directory, "multi-create-dedicated");
    dedicated_request.id = container_id("multi-dedicated");
    let dedicated_record = service
        .create(dedicated_request.clone())
        .await
        .expect("create dedicated container");
    assert_eq!(dedicated_record.driver, DriverKind::LibkrunWhpx);

    let mut shared_request = create_request(&bundle_directory, "multi-create-shared");
    shared_request.id = container_id("multi-shared");
    shared_request.isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: identifier("multi-domain", TrustDomainId::new),
    };
    let shared_record = service
        .create(shared_request.clone())
        .await
        .expect("create shared-guest container");
    assert_eq!(shared_record.driver, DriverKind::LibkrunHvf);
    assert_eq!(
        dedicated
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );
    assert_eq!(
        shared
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );

    drop(service);
    let reversed: Vec<Arc<dyn RuntimeDriver>> = vec![shared.clone(), dedicated.clone()];
    let reopened = HostRuntimeService::open_with_drivers(&state_root, reversed)
        .await
        .expect("reopen multi-driver service");
    reopened
        .start(StartRequest {
            context: OperationContext::new(operation_id("multi-start-dedicated")),
            target: ContainerTarget::exact(
                dedicated_request.id.clone(),
                dedicated_record.generation,
            ),
        })
        .await
        .expect("start dedicated container after reopen");
    reopened
        .start(StartRequest {
            context: OperationContext::new(operation_id("multi-start-shared")),
            target: ContainerTarget::exact(shared_request.id, shared_record.generation),
        })
        .await
        .expect("start shared container after reopen");
    assert_eq!(
        dedicated
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Start(_)))
            .count(),
        1
    );
    assert_eq!(
        shared
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Start(_)))
            .count(),
        1
    );

    let dedicated_target =
        ContainerTarget::exact(dedicated_request.id.clone(), dedicated_record.generation);
    reopened
        .kill(KillRequest {
            context: OperationContext::new(operation_id("multi-kill-dedicated")),
            target: dedicated_target.clone(),
            signal: Signal::new(15).expect("signal"),
            all: true,
        })
        .await
        .expect("stop dedicated container");
    reopened
        .delete(DeleteRequest {
            context: OperationContext::new(operation_id("multi-delete-dedicated")),
            target: dedicated_target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete dedicated container");

    let mut reused = create_request(&bundle_directory, "multi-recreate-shared");
    reused.id = dedicated_request.id;
    reused.isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: identifier("multi-domain", TrustDomainId::new),
    };
    let reused_record = reopened
        .create(reused.clone())
        .await
        .expect("recreate ID with shared-guest isolation");
    assert!(reused_record.generation > dedicated_record.generation);
    assert_eq!(reused_record.driver, DriverKind::LibkrunHvf);
    reopened
        .start(StartRequest {
            context: OperationContext::new(operation_id("multi-start-reused")),
            target: ContainerTarget::exact(reused.id, reused_record.generation),
        })
        .await
        .expect("start reused ID through recorded shared driver");
    assert_eq!(
        dedicated
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Start(_)))
            .count(),
        1,
        "reused ID must not return to its previous driver"
    );
    assert_eq!(
        shared
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Start(_)))
            .count(),
        2,
        "reused ID must follow the new generation's driver"
    );

    let info = reopened.features().await.expect("multi-driver features");
    assert_eq!(
        info.drivers
            .driver(DriverKind::LibkrunWhpx)
            .expect("dedicated driver")
            .readiness,
        DriverReadiness::Supported
    );
    assert_eq!(
        info.drivers
            .driver(DriverKind::LibkrunHvf)
            .expect("shared driver")
            .readiness,
        DriverReadiness::Supported
    );
}

#[tokio::test]
async fn recreated_created_recovery_rebinds_pid_and_repairs_create_replay() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("recreated-created-state");
    let first_driver = Arc::new(RecordingDriver::supported());
    let service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open first owner");
    let create = create_request(&bundle_directory, "recreated-created-create");
    let original = service.create(create.clone()).await.expect("first create");
    assert_eq!(*original.state.pid(), Some(4_242));
    drop(service);

    let replacement = Arc::new(RecordingDriver::supported());
    replacement.set_recreated_created_recovery(
        DriverState::created(5_252).expect("replacement created state"),
    );
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&replacement) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen around replacement owner");
    let recovered = reopened
        .list(ListRequest::default())
        .await
        .expect("list recovered record")
        .pop()
        .expect("one recovered record");
    assert_eq!(recovered.generation, original.generation);
    assert_eq!(*recovered.state.pid(), Some(5_252));

    let replayed = reopened
        .create(create.clone())
        .await
        .expect("repair and replay completed create");
    assert_eq!(replayed, recovered);
    assert_eq!(
        replacement
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Recover(_)))
            .count(),
        1
    );
    assert!(replacement
        .calls()
        .iter()
        .all(|call| !matches!(call, DriverCall::Create(_))));
    drop(reopened);

    let journal_reader = Arc::new(RecordingDriver::supported());
    let reopened_again = HostRuntimeService::open(
        &state_root,
        Arc::clone(&journal_reader) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen after journal repair");
    assert_eq!(
        reopened_again
            .create(create)
            .await
            .expect("replay repaired create journal"),
        recovered
    );
    drop(reopened_again);

    let unprivileged_recovery = Arc::new(RecordingDriver::supported());
    unprivileged_recovery
        .set_recovery_observation(DriverState::created(6_262).expect("different created state"));
    let error = HostRuntimeService::open(
        &state_root,
        Arc::clone(&unprivileged_recovery) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect_err("ordinary recovery must not replace a created PID");
    assert_eq!(error.code, ErrorCode::Conflict);
}

#[tokio::test]
async fn recreated_running_recovery_rebinds_pid_and_repairs_create_and_start_replay() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("recreated-running-state");
    let first_driver = Arc::new(RecordingDriver::supported());
    let service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open first owner");
    let create = create_request(&bundle_directory, "recreated-running-create");
    let created = service.create(create.clone()).await.expect("first create");
    let start = StartRequest {
        context: OperationContext::new(operation_id("recreated-running-start")),
        target: ContainerTarget::exact(create.id.clone(), created.generation),
    };
    let original_running = service.start(start.clone()).await.expect("first start");
    assert_eq!(*original_running.state.status(), ContainerState::Running);
    assert_eq!(*original_running.state.pid(), Some(4_242));
    drop(service);

    let replacement = Arc::new(RecordingDriver::supported());
    replacement.set_recreated_running_recovery(
        DriverState::running(5_252).expect("replacement running state"),
    );
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&replacement) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen around replacement running owner");
    let recovered = reopened
        .list(ListRequest::default())
        .await
        .expect("list recovered running record")
        .pop()
        .expect("one recovered running record");
    assert_eq!(*recovered.state.status(), ContainerState::Running);
    assert_eq!(*recovered.state.pid(), Some(5_252));

    let replayed_create = reopened
        .create(create.clone())
        .await
        .expect("repair and replay completed create");
    assert_eq!(*replayed_create.state.status(), ContainerState::Created);
    assert_eq!(*replayed_create.state.pid(), Some(5_252));
    assert_eq!(replayed_create.generation, recovered.generation);
    assert_eq!(
        reopened
            .start(start.clone())
            .await
            .expect("repair and replay completed start"),
        recovered
    );
    assert_eq!(
        replacement
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Recover(_)))
            .count(),
        1
    );
    assert!(replacement
        .calls()
        .iter()
        .all(|call| { !matches!(call, DriverCall::Create(_) | DriverCall::Start(_)) }));
    drop(reopened);

    let journal_reader = Arc::new(RecordingDriver::supported());
    journal_reader
        .set_recovery_observation(DriverState::running(5_252).expect("stable running observation"));
    let reopened_again = HostRuntimeService::open(
        &state_root,
        Arc::clone(&journal_reader) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen after running journal repair");
    assert_eq!(
        *reopened_again
            .create(create)
            .await
            .expect("replay rebound create journal")
            .state
            .pid(),
        Some(5_252)
    );
    assert_eq!(
        reopened_again
            .start(start)
            .await
            .expect("replay rebound start journal"),
        recovered
    );
    drop(reopened_again);

    let unprivileged_recovery = Arc::new(RecordingDriver::supported());
    unprivileged_recovery
        .set_recovery_observation(DriverState::running(6_262).expect("different running state"));
    let error = HostRuntimeService::open(
        &state_root,
        Arc::clone(&unprivileged_recovery) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect_err("ordinary recovery must not replace a running PID");
    assert_eq!(error.code, ErrorCode::Conflict);
}

#[tokio::test]
async fn recreated_running_recovery_preserves_an_interrupted_kill() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("recreated-running-kill-state");
    let first_driver = Arc::new(RecordingDriver::supported());
    let service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open first kill owner");
    let create = create_request(&bundle_directory, "recreated-running-kill-create");
    let created = service.create(create.clone()).await.expect("first create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let start = StartRequest {
        context: OperationContext::new(operation_id("recreated-running-kill-start")),
        target: target.clone(),
    };
    service.start(start.clone()).await.expect("first start");
    let kill = KillRequest {
        context: OperationContext::new(operation_id("recreated-running-kill")),
        target: target.clone(),
        signal: Signal::new(9).expect("kill signal"),
        all: true,
    };
    first_driver.fail_next(
        "kill",
        Error::new(ErrorCode::Unavailable, "first owner disconnected")
            .for_operation("kill")
            .retryable(true),
    );
    let error = service
        .kill(kill.clone())
        .await
        .expect_err("first kill must remain resumable");
    assert!(error.retryable);
    drop(service);

    let replacement = Arc::new(RecordingDriver::supported());
    replacement.set_recreated_running_recovery(
        DriverState::running(5_252).expect("replacement running state"),
    );
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&replacement) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen around replacement kill owner");
    let replayed_create = reopened
        .create(create)
        .await
        .expect("repair Create response while Kill remains active");
    assert_eq!(*replayed_create.state.status(), ContainerState::Created);
    assert_eq!(*replayed_create.state.pid(), Some(5_252));
    let replayed_start = reopened
        .start(start)
        .await
        .expect("repair Start response while Kill remains active");
    assert_eq!(*replayed_start.state.status(), ContainerState::Running);
    assert_eq!(*replayed_start.state.pid(), Some(5_252));
    let stopped = reopened
        .kill(kill)
        .await
        .expect("resume Kill through replacement owner");
    assert_eq!(*stopped.state.status(), ContainerState::Stopped);
    assert_eq!(*stopped.state.pid(), None);
    assert_eq!(stopped.generation, created.generation);
    assert_eq!(
        replacement
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Recover(_)))
            .count(),
        1
    );
    assert_eq!(
        replacement
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Kill(_)))
            .count(),
        1
    );
}

#[tokio::test]
async fn service_open_reconciles_each_record_with_its_recorded_driver() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("recovery-routing-state");
    let dedicated = Arc::new(RecordingDriver::supported());
    let shared = Arc::new(RecordingDriver::shared_guest_supported());
    let drivers: Vec<Arc<dyn RuntimeDriver>> = vec![dedicated.clone(), shared.clone()];
    let service = HostRuntimeService::open_with_drivers(&state_root, drivers)
        .await
        .expect("open recovery routing service");

    let mut dedicated_request = create_request(&bundle_directory, "recovery-create-dedicated");
    dedicated_request.id = container_id("recovery-dedicated");
    let dedicated_record = service
        .create(dedicated_request.clone())
        .await
        .expect("create dedicated recovery record");
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("recovery-start-dedicated")),
            target: ContainerTarget::exact(
                dedicated_request.id.clone(),
                dedicated_record.generation,
            ),
        })
        .await
        .expect("start dedicated recovery record");

    let mut shared_request = create_request(&bundle_directory, "recovery-create-shared");
    shared_request.id = container_id("recovery-shared");
    shared_request.isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: identifier("recovery-domain", TrustDomainId::new),
    };
    let shared_record = service
        .create(shared_request.clone())
        .await
        .expect("create shared recovery record");
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("recovery-start-shared")),
            target: ContainerTarget::exact(shared_request.id.clone(), shared_record.generation),
        })
        .await
        .expect("start shared recovery record");
    drop(service);

    dedicated.set_recovery_observation(DriverState::stopped());
    let reversed: Vec<Arc<dyn RuntimeDriver>> = vec![shared, dedicated.clone()];
    let reopened = HostRuntimeService::open_with_drivers(&state_root, reversed)
        .await
        .expect("reopen recovery routing service");
    let records = reopened
        .list(ListRequest::default())
        .await
        .expect("list reconciled records");
    let recovered_dedicated = records
        .iter()
        .find(|record| record.state.id() == dedicated_request.id.as_str())
        .expect("recovered dedicated record");
    let unchanged_shared = records
        .iter()
        .find(|record| record.state.id() == shared_request.id.as_str())
        .expect("unchanged shared record");
    assert_eq!(recovered_dedicated.state.status(), &ContainerState::Stopped);
    assert_eq!(unchanged_shared.state.status(), &ContainerState::Running);

    let recovery_calls = dedicated
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            DriverCall::Recover(record) => Some(record),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(recovery_calls.len(), 1);
    assert_eq!(recovery_calls[0].driver, DriverKind::LibkrunWhpx);
    assert_eq!(recovery_calls[0].state.id(), dedicated_request.id.as_str());
}

#[tokio::test]
async fn service_open_rejects_missing_or_drifted_durable_driver_bindings() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("driver-audit-state");
    let dedicated = Arc::new(RecordingDriver::supported());
    let service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&dedicated) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open initial service");
    let mut request = create_request(&bundle_directory, "driver-audit-create");
    request.id = container_id("driver-audit-container");
    let record = service
        .create(request)
        .await
        .expect("create durable container");
    drop(service);

    let missing: Vec<Arc<dyn RuntimeDriver>> =
        vec![Arc::new(RecordingDriver::shared_guest_supported())];
    let error = HostRuntimeService::open_with_drivers(&state_root, missing)
        .await
        .expect_err("missing recorded driver must fail service open");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.message.contains(record.state.id().as_str()));
    assert!(error.message.contains("LibkrunWhpx"));

    let mut drifted = RecordingDriver::supported();
    drifted.capability.isolation_classes = vec![IsolationClass::SharedGuestKernel];
    let error = HostRuntimeService::open(&state_root, Arc::new(drifted))
        .await
        .expect_err("recorded driver isolation drift must fail service open");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains(record.state.id().as_str()));
    assert!(error.message.contains("DedicatedVm"));

    let calls_before_reopen = dedicated.calls().len();
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&dedicated) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("matching recorded driver reopens service");
    assert_eq!(dedicated.calls().len(), calls_before_reopen);
    assert_eq!(
        reopened
            .list(ListRequest::default())
            .await
            .expect("list audited state"),
        vec![record]
    );
}

#[tokio::test]
async fn multi_driver_registration_rejects_ambiguous_or_inconsistent_sets_before_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");

    let empty_root = temporary.path().join("empty");
    let error = HostRuntimeService::open_with_drivers(&empty_root, Vec::new())
        .await
        .expect_err("empty driver set must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("at least one"));
    assert!(!empty_root.exists());

    let first = Arc::new(RecordingDriver::supported());
    let mut overlapping = RecordingDriver::supported();
    overlapping.capability.driver = DriverKind::LibkrunHvf;
    let overlap_root = temporary.path().join("overlap");
    let overlap_drivers: Vec<Arc<dyn RuntimeDriver>> = vec![first, Arc::new(overlapping)];
    let error = HostRuntimeService::open_with_drivers(&overlap_root, overlap_drivers)
        .await
        .expect_err("overlapping isolation must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("claimed by both"));
    assert!(!overlap_root.exists());

    let first = Arc::new(RecordingDriver::supported());
    let mut inconsistent = RecordingDriver::shared_guest_supported();
    inconsistent.operations.pop();
    let inconsistent_root = temporary.path().join("inconsistent");
    let inconsistent_drivers: Vec<Arc<dyn RuntimeDriver>> = vec![first, Arc::new(inconsistent)];
    let error = HostRuntimeService::open_with_drivers(&inconsistent_root, inconsistent_drivers)
        .await
        .expect_err("inconsistent operation sets must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("different operation set"));
    assert!(!inconsistent_root.exists());

    let first = Arc::new(RecordingDriver::supported());
    let mut inconsistent_hooks = RecordingDriver::shared_guest_supported();
    inconsistent_hooks.hooks.push(OciHookPhase::Prestart);
    let hook_root = temporary.path().join("inconsistent-hooks");
    let hook_drivers: Vec<Arc<dyn RuntimeDriver>> = vec![first, Arc::new(inconsistent_hooks)];
    let error = HostRuntimeService::open_with_drivers(&hook_root, hook_drivers)
        .await
        .expect_err("inconsistent Hook sets must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("different OCI hook set"));
    assert!(!hook_root.exists());
}

#[cfg(any(unix, windows))]
const PROCESS_OWNER_CHILD_ENV: &str = "A3S_OCI_TEST_RUNTIME_OWNER_CHILD";
#[cfg(any(unix, windows))]
const PROCESS_OWNER_STATE_ENV: &str = "A3S_OCI_TEST_RUNTIME_OWNER_STATE";
#[cfg(any(unix, windows))]
const PROCESS_OWNER_ENDPOINT_ENV: &str = "A3S_OCI_TEST_RUNTIME_OWNER_ENDPOINT";
#[cfg(any(unix, windows))]
const PROCESS_OWNER_READY_ENV: &str = "A3S_OCI_TEST_RUNTIME_OWNER_READY";
#[cfg(any(unix, windows))]
const PROCESS_OWNER_LOG_ENV: &str = "A3S_OCI_TEST_RUNTIME_OWNER_LOG";
#[cfg(any(unix, windows))]
const PROCESS_OWNER_TEST_NAME: &str =
    "service::tests::retained_sdk_client_recovers_after_runtime_owner_process_restart";

#[cfg(any(unix, windows))]
struct RuntimeOwnerChild {
    child: Option<std::process::Child>,
    stderr_path: PathBuf,
}

#[cfg(any(unix, windows))]
impl RuntimeOwnerChild {
    fn spawn(
        state_root: &Path,
        endpoint: &std::ffi::OsStr,
        ready_path: &Path,
        log_path: &Path,
        stderr_path: PathBuf,
    ) -> Self {
        let stderr = std::fs::File::create(&stderr_path).expect("create owner stderr file");
        let child = std::process::Command::new(
            std::env::current_exe().expect("resolve runtime test executable"),
        )
        .args(["--exact", PROCESS_OWNER_TEST_NAME, "--nocapture"])
        .env(PROCESS_OWNER_CHILD_ENV, "1")
        .env(PROCESS_OWNER_STATE_ENV, state_root)
        .env(PROCESS_OWNER_ENDPOINT_ENV, endpoint)
        .env(PROCESS_OWNER_READY_ENV, ready_path)
        .env(PROCESS_OWNER_LOG_ENV, log_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn out-of-process runtime owner");
        Self {
            child: Some(child),
            stderr_path,
        }
    }

    fn wait_until_ready(&mut self, ready_path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if ready_path.is_file() {
                return;
            }
            if let Some(status) = self
                .child
                .as_mut()
                .expect("runtime owner child")
                .try_wait()
                .expect("inspect runtime owner child")
            {
                let stderr = std::fs::read_to_string(&self.stderr_path).unwrap_or_default();
                panic!("runtime owner exited before readiness ({status}): {stderr}");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "runtime owner did not become ready: {}",
                std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn terminate(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        child.wait().expect("reap runtime owner child");
    }
}

#[cfg(any(unix, windows))]
impl Drop for RuntimeOwnerChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(any(unix, windows))]
fn required_process_owner_path(name: &'static str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("missing runtime owner child environment {name}"))
}

#[cfg(any(unix, windows))]
async fn run_process_owner_child() {
    let state_root = required_process_owner_path(PROCESS_OWNER_STATE_ENV);
    let ready_path = required_process_owner_path(PROCESS_OWNER_READY_ENV);
    let log_path = required_process_owner_path(PROCESS_OWNER_LOG_ENV);
    let driver: Arc<dyn RuntimeDriver> = Arc::new(RecordingDriver::process_fixture(log_path));
    let service = HostRuntimeService::open(state_root, driver)
        .await
        .expect("open durable child host service");

    #[cfg(windows)]
    {
        let endpoint_name = std::env::var(PROCESS_OWNER_ENDPOINT_ENV)
            .expect("Windows runtime owner endpoint environment");
        let endpoint = a3s_oci_sdk::LocalIpcEndpoint::windows_named_pipe(endpoint_name)
            .expect("valid child named-pipe endpoint");
        let owner = crate::WindowsHostService::bind(endpoint, service)
            .expect("bind child Windows host service");
        std::fs::write(&ready_path, b"ready").expect("publish child readiness");
        owner
            .serve_until(std::future::pending())
            .await
            .expect("serve child Windows host service");
    }

    #[cfg(unix)]
    {
        let socket_path = required_process_owner_path(PROCESS_OWNER_ENDPOINT_ENV);
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).expect("remove stale child SDK socket");
        }
        let listener =
            tokio::net::UnixListener::bind(&socket_path).expect("bind child Unix SDK socket");
        let service: Arc<dyn OciRuntimeService> = Arc::new(service);
        std::fs::write(&ready_path, b"ready").expect("publish child readiness");
        let (stream, _) = listener.accept().await.expect("accept parent SDK client");
        a3s_oci_sdk::serve_transport_connection(service, stream)
            .await
            .expect("serve child Unix SDK connection");
    }
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn retained_sdk_client_recovers_after_runtime_owner_process_restart() {
    if std::env::var_os(PROCESS_OWNER_CHILD_ENV).is_some() {
        run_process_owner_child().await;
        return;
    }

    let temporary = tempfile::tempdir().expect("temporary process-restart directory");
    let state_root = temporary.path().join("state");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let call_log = temporary.path().join("driver-calls.log");

    #[cfg(windows)]
    let (endpoint_value, endpoint) = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_PIPE: AtomicU64 = AtomicU64::new(30_000);
        let name = format!(
            r"\\.\pipe\a3s-oci-owner-restart-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        );
        let endpoint = a3s_oci_sdk::LocalIpcEndpoint::windows_named_pipe(name.clone())
            .expect("valid parent named-pipe endpoint");
        (std::ffi::OsString::from(name), endpoint)
    };
    #[cfg(unix)]
    let (endpoint_value, endpoint) = {
        let path = temporary.path().join("runtime.sock");
        let endpoint = a3s_oci_sdk::LocalIpcEndpoint::unix_socket(path.clone())
            .expect("valid parent Unix endpoint");
        (path.into_os_string(), endpoint)
    };

    let first_ready = temporary.path().join("owner-1.ready");
    let mut first_owner = RuntimeOwnerChild::spawn(
        &state_root,
        &endpoint_value,
        &first_ready,
        &call_log,
        temporary.path().join("owner-1.stderr"),
    );
    first_owner.wait_until_ready(&first_ready);
    let client = a3s_oci_sdk::RuntimeClient::connect(&endpoint)
        .await
        .expect("connect retained SDK client to first owner");
    let create = create_request(&bundle_directory, "process-restart-create");
    let created = client
        .create(create.clone())
        .await
        .expect("create through first owner");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let start = StartRequest {
        context: OperationContext::new(operation_id("process-restart-start")),
        target: target.clone(),
    };
    let running = client
        .start(start.clone())
        .await
        .expect("start through first owner");
    assert_eq!(running.state.status(), &ContainerState::Running);
    let mut exec = exec_request(target.clone(), "process-restart-exec", "surviving-worker");
    exec.io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    let process = client
        .exec(exec.clone())
        .await
        .expect("start process session through first owner");
    assert_eq!(process.target.process_id.as_str(), "surviving-worker");

    first_owner.terminate();
    let disconnected = client
        .state(StateRequest {
            target: target.clone(),
        })
        .await
        .expect_err("first request after owner death must expose the disconnect");
    assert_eq!(disconnected.code, ErrorCode::Unavailable);
    assert!(disconnected.retryable);

    let second_ready = temporary.path().join("owner-2.ready");
    let mut second_owner = RuntimeOwnerChild::spawn(
        &state_root,
        &endpoint_value,
        &second_ready,
        &call_log,
        temporary.path().join("owner-2.stderr"),
    );
    second_owner.wait_until_ready(&second_ready);
    let recovered = client
        .state(StateRequest {
            target: target.clone(),
        })
        .await
        .expect("retained client must reconnect to replacement owner");
    assert_eq!(recovered, running);
    assert_eq!(
        client
            .create(create.clone())
            .await
            .expect("durable create replay after process restart"),
        created
    );
    assert_eq!(
        client
            .start(start)
            .await
            .expect("durable start replay after process restart"),
        running
    );
    assert_eq!(
        client
            .exec(exec)
            .await
            .expect("durable exec replay after process restart"),
        process
    );
    let inventory = client
        .processes(ProcessesRequest {
            target: target.clone(),
        })
        .await
        .expect("recover live process inventory after owner restart");
    assert!(inventory.iter().any(|candidate| candidate == &process));
    client
        .write_stdin(WriteStdinRequest {
            context: OperationContext::new(operation_id("process-restart-stdin")),
            process: process.target.clone(),
            data: b"after restart\n".to_vec(),
        })
        .await
        .expect("continue process stdin after owner restart");
    let process_signal = Signal::new(15).expect("valid process signal");
    client
        .signal_process(SignalProcessRequest {
            context: OperationContext::new(operation_id("process-restart-process-signal")),
            process: process.target.clone(),
            signal: process_signal,
        })
        .await
        .expect("signal recovered process session");
    assert_eq!(
        client
            .wait_process(WaitProcessRequest {
                process: process.target.clone(),
                timeout_ms: Some(1_000),
            })
            .await
            .expect("wait for recovered process session"),
        ExitStatus::signaled(process_signal.get(), false).expect("process exit status")
    );
    let output = client
        .read_output(ReadOutputRequest {
            process: process.target,
            after_sequence: 0,
            max_bytes: 4_096,
            wait_timeout_ms: Some(0),
        })
        .await
        .expect("read recovered process output");
    assert_eq!(
        output
            .iter()
            .flat_map(|chunk| chunk.data.iter().copied())
            .collect::<Vec<_>>(),
        b"runtime owner process\n"
    );
    assert!(output.iter().any(|chunk| chunk.eof));

    let calls = std::fs::read_to_string(&call_log).expect("read process driver call log");
    assert_eq!(calls.lines().filter(|call| *call == "create").count(), 1);
    assert_eq!(calls.lines().filter(|call| *call == "start").count(), 1);
    assert_eq!(calls.lines().filter(|call| *call == "exec").count(), 1);
    assert_eq!(calls.lines().filter(|call| *call == "recover").count(), 1);
    assert_eq!(
        calls.lines().filter(|call| *call == "write-stdin").count(),
        1
    );
    assert_eq!(
        calls
            .lines()
            .filter(|call| *call == "signal-process")
            .count(),
        1
    );
    assert_eq!(
        calls.lines().filter(|call| *call == "read-output").count(),
        1
    );

    client
        .kill(KillRequest {
            context: OperationContext::new(operation_id("process-restart-kill")),
            target: target.clone(),
            signal: Signal::new(9).expect("valid signal"),
            all: true,
        })
        .await
        .expect("kill recovered process fixture");
    client
        .delete(DeleteRequest {
            context: OperationContext::new(operation_id("process-restart-delete")),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete recovered process fixture");
    let calls = std::fs::read_to_string(&call_log).expect("read final process driver call log");
    assert_eq!(calls.lines().filter(|call| *call == "create").count(), 1);
    assert_eq!(calls.lines().filter(|call| *call == "start").count(), 1);
    assert_eq!(calls.lines().filter(|call| *call == "kill").count(), 1);
    assert_eq!(calls.lines().filter(|call| *call == "delete").count(), 1);
    let process_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(call_log.with_extension("processes.json"))
            .expect("read cleaned process fixture state"),
    )
    .expect("decode cleaned process fixture state");
    assert_eq!(process_state, serde_json::json!([]));
    second_owner.terminate();
}
