use a3s_oci_agent_protocol::AgentInheritedDescriptorSchema;
use a3s_oci_core::DriverCapability;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources, Process};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, ContainerRecord, ContainerStats, ContainerTarget,
    CreateAttachments, DeleteMode, Error, ErrorCode, ExitStatus, FileRequest, FileResponse,
    FilesystemRequest, FilesystemResponse, IsolationRequest, OciBundle, OperationContext,
    OperationId, OutputChunk, ProcessIo, ProcessRecord, ProcessTarget, Result, RuntimeOperation,
    Signal, TerminalSize,
};

const CORE_DRIVER_OPERATIONS: [RuntimeOperation; 5] = [
    RuntimeOperation::Create,
    RuntimeOperation::State,
    RuntimeOperation::Start,
    RuntimeOperation::Kill,
    RuntimeOperation::Delete,
];

/// Process-local resources attached to a native create request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DriverCreateAttachments {
    /// Normal SDK or guest-protocol create with no inherited descriptors.
    #[default]
    None,
    /// A3S Box exec listener, PTY listener, and dedicated init log.
    #[cfg(target_os = "linux")]
    NativeControl(crate::NativeControlDescriptors),
}

impl DriverCreateAttachments {
    /// Stable logical schema without raw descriptor or inode identity.
    #[must_use]
    pub fn schema(&self) -> Option<AgentInheritedDescriptorSchema> {
        match self {
            Self::None => None,
            #[cfg(target_os = "linux")]
            Self::NativeControl(_) => Some(AgentInheritedDescriptorSchema::a3s_box_control_v1()),
        }
    }

    /// Whether the create carries process-local native resources.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// OCI hook phases implemented by one exact runtime driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OciHookPhase {
    /// Deprecated runtime-namespace create hook retained by OCI 1.x.
    Prestart,
    /// Runtime-namespace hook after the environment is created.
    CreateRuntime,
    /// Container-namespace hook before pivoting into the root filesystem.
    CreateContainer,
    /// Container-namespace hook before the configured process executes.
    StartContainer,
    /// Runtime-namespace hook after the configured process executes.
    Poststart,
    /// Runtime-namespace warning-only hook after container destruction.
    Poststop,
}

impl OciHookPhase {
    /// Every standardized phase in normative lifecycle order.
    pub const ALL: [Self; 6] = [
        Self::Prestart,
        Self::CreateRuntime,
        Self::CreateContainer,
        Self::StartContainer,
        Self::Poststart,
        Self::Poststop,
    ];

    /// Exact spelling used by the OCI features document.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prestart => "prestart",
            Self::CreateRuntime => "createRuntime",
            Self::CreateContainer => "createContainer",
            Self::StartContainer => "startContainer",
            Self::Poststart => "poststart",
            Self::Poststop => "poststop",
        }
    }
}

/// Driver-reported init-process state at one exact container generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverState {
    status: ContainerState,
    pid: Option<i32>,
    paused: bool,
}

impl DriverState {
    /// Report an init process prepared behind the OCI create/start barrier.
    pub fn created(pid: i32) -> Result<Self> {
        Self::with_process(ContainerState::Created, pid)
    }

    /// Report an init process whose configured user program is running.
    pub fn running(pid: i32) -> Result<Self> {
        Self::with_process(ContainerState::Running, pid)
    }

    /// Report a container whose init process has exited.
    #[must_use]
    pub const fn stopped() -> Self {
        Self {
            status: ContainerState::Stopped,
            pid: None,
            paused: false,
        }
    }

    /// OCI lifecycle status observed by the driver.
    #[must_use]
    pub const fn status(self) -> ContainerState {
        self.status
    }

    /// Positive host- or guest-visible init PID when the process still exists.
    #[must_use]
    pub const fn pid(self) -> Option<i32> {
        self.pid
    }

    /// Whether the driver observed the container cgroup as frozen.
    #[must_use]
    pub const fn paused(self) -> bool {
        self.paused
    }

    /// Attach an exact freezer observation to a live driver state.
    pub fn with_paused(mut self, paused: bool) -> Result<Self> {
        if paused && self.status != ContainerState::Running {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("a {} driver state cannot be paused", self.status),
            )
            .for_operation("construct-driver-state"));
        }
        self.paused = paused;
        Ok(self)
    }

    fn with_process(status: ContainerState, pid: i32) -> Result<Self> {
        if pid <= 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("driver init PID must be positive; received {pid}"),
            )
            .for_operation("construct-driver-state"));
        }
        Ok(Self {
            status,
            pid: Some(pid),
            paused: false,
        })
    }
}

/// Idempotent driver evidence returned while the host opens durable state.
///
/// A state observation is committed before the service accepts requests. An
/// exact init exit result is valid only with a stopped observation and is then
/// cached through the normal durable process-wait path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DriverRecovery {
    observation: Option<DriverState>,
    init_exit_status: Option<ExitStatus>,
    recreated_process: RecreatedProcess,
    recreated_exec_processes: Vec<ProcessRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RecreatedProcess {
    #[default]
    None,
    Created,
    Running,
    RunningPaused,
}

impl DriverRecovery {
    /// Leave the durable record unchanged so its active operation can resume.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            observation: None,
            init_exit_status: None,
            recreated_process: RecreatedProcess::None,
            recreated_exec_processes: Vec::new(),
        }
    }

    /// Commit one exact driver state without claiming terminal evidence.
    #[must_use]
    pub const fn observed(observation: DriverState) -> Self {
        Self {
            observation: Some(observation),
            init_exit_status: None,
            recreated_process: RecreatedProcess::None,
            recreated_exec_processes: Vec::new(),
        }
    }

    /// Report a pre-start process rebuilt by a replacement driver owner.
    ///
    /// This explicitly allows the durable `created` PID and its completed
    /// Create response to move to the fresh owner's exact process identity.
    /// Running and stopped workloads cannot use this recovery mode.
    pub fn recreated_created(observation: DriverState) -> Result<Self> {
        if observation.status() != ContainerState::Created || observation.paused() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recreated process recovery requires an unpaused created driver state",
            )
            .for_operation("construct-driver-recovery"));
        }
        Ok(Self {
            observation: Some(observation),
            init_exit_status: None,
            recreated_process: RecreatedProcess::Created,
            recreated_exec_processes: Vec::new(),
        })
    }

    /// Report a running init process rebuilt by a replacement driver owner.
    ///
    /// This allows the durable running PID plus completed Create and Start
    /// responses to be rebound to the fresh owner's exact process identity.
    /// Paused and stopped workloads require their own stronger recovery proof.
    pub fn recreated_running(observation: DriverState) -> Result<Self> {
        Self::recreated_running_with_processes(observation, Vec::new())
    }

    /// Report a frozen running init process rebuilt by a replacement owner.
    ///
    /// The replacement must recreate and start the process, then reapply the
    /// durable freezer state before returning this evidence. Live Exec
    /// recovery for paused containers is not accepted by this mode.
    pub fn recreated_paused_running(observation: DriverState) -> Result<Self> {
        if observation.status() != ContainerState::Running || !observation.paused() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recreated paused recovery requires a paused running driver state",
            )
            .for_operation("construct-driver-recovery"));
        }
        if observation.pid().is_none_or(|pid| pid <= 0) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recreated paused recovery requires a positive init PID",
            )
            .for_operation("construct-driver-recovery"));
        }
        Ok(Self {
            observation: Some(observation),
            init_exit_status: None,
            recreated_process: RecreatedProcess::RunningPaused,
            recreated_exec_processes: Vec::new(),
        })
    }

    /// Report a running init process and every live exec process rebuilt by a
    /// replacement driver owner.
    ///
    /// The host requires this list to match its completed, non-terminal exec
    /// records exactly before it accepts requests. It then rebinds only the
    /// driver-visible PIDs; container generation, process ID, and terminal mode
    /// remain fenced by durable state. Drivers must not report prepared execs
    /// that have no committed Host response or processes with terminal evidence.
    pub fn recreated_running_with_processes(
        observation: DriverState,
        mut processes: Vec<ProcessRecord>,
    ) -> Result<Self> {
        if observation.status() != ContainerState::Running || observation.paused() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recreated process recovery requires an unpaused running driver state",
            )
            .for_operation("construct-driver-recovery"));
        }
        let init_pid = observation
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "recreated running recovery requires a positive init PID",
                )
                .for_operation("construct-driver-recovery")
            })?;
        for process in &processes {
            if process.target.process_id.is_init()
                || process.target.container.generation.is_none()
                || process.pid.is_none()
                || process.pid == Some(0)
                || process.pid == Some(init_pid)
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "recreated exec recovery requires an exact non-init target and a positive PID distinct from init",
                )
                .for_operation("construct-driver-recovery"));
            }
        }
        processes.sort_by(|left, right| {
            left.target
                .container
                .id
                .cmp(&right.target.container.id)
                .then_with(|| {
                    left.target
                        .container
                        .generation
                        .cmp(&right.target.container.generation)
                })
                .then_with(|| left.target.process_id.cmp(&right.target.process_id))
        });
        if processes
            .windows(2)
            .any(|pair| pair[0].target == pair[1].target)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recreated exec recovery contains a duplicate process target",
            )
            .for_operation("construct-driver-recovery"));
        }
        if processes.first().is_some_and(|first| {
            processes
                .iter()
                .any(|process| process.target.container != first.target.container)
        }) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recreated exec recovery spans more than one container generation",
            )
            .for_operation("construct-driver-recovery"));
        }
        let mut pids = processes
            .iter()
            .filter_map(|process| process.pid)
            .collect::<Vec<_>>();
        pids.sort_unstable();
        if pids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recreated exec recovery contains a duplicate PID",
            )
            .for_operation("construct-driver-recovery"));
        }
        Ok(Self {
            observation: Some(observation),
            init_exit_status: None,
            recreated_process: RecreatedProcess::Running,
            recreated_exec_processes: processes,
        })
    }

    /// Commit a stopped observation plus the exact init terminal result.
    pub fn stopped_with_exit(init_exit_status: ExitStatus) -> Result<Self> {
        init_exit_status.validate()?;
        Ok(Self {
            observation: Some(DriverState::stopped()),
            init_exit_status: Some(init_exit_status),
            recreated_process: RecreatedProcess::None,
            recreated_exec_processes: Vec::new(),
        })
    }

    pub(crate) const fn recreated_process(&self) -> RecreatedProcess {
        self.recreated_process
    }

    pub(crate) fn recreated_exec_processes(&self) -> &[ProcessRecord] {
        &self.recreated_exec_processes
    }

    /// Consume the recovery result into its durable components.
    #[must_use]
    pub fn into_parts(self) -> (Option<DriverState>, Option<ExitStatus>) {
        (self.observation, self.init_exit_status)
    }
}

/// Exact create input passed from durable host orchestration to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverCreateRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus its allocated exact generation.
    pub target: ContainerTarget,
    /// Immutable bundle reconstructed from the durable configuration snapshot.
    pub bundle: OciBundle,
    /// Isolation contract already checked against the driver capability.
    pub isolation: IsolationRequest,
    /// Host-side standard-I/O disposition for the init process.
    pub io: ProcessIo,
    /// Versioned, digest-bound public attachment contract.
    pub attachment_contract: CreateAttachments,
    /// Process-local native resources, excluded from the wire protocol.
    pub attachments: DriverCreateAttachments,
}

/// Exact start input. The immutable durable bundle is supplied again so a
/// restarted driver cannot execute a changed host bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverStartRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus its exact generation.
    pub target: ContainerTarget,
    /// Immutable durable bundle revalidated for the start phase.
    pub bundle: OciBundle,
}

/// Exact OCI signal input passed to a driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverKillRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus its exact generation.
    pub target: ContainerTarget,
    /// Positive Linux signal number to deliver unchanged.
    pub signal: Signal,
    /// Whether the signal applies to every process in the container.
    pub all: bool,
}

/// Exact cleanup input passed to a driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverDeleteRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus its exact generation.
    pub target: ContainerTarget,
    /// Stopped-only or force cleanup behavior requested by the caller.
    pub mode: DeleteMode,
}

/// Exact init-process wait input passed to a driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverWaitRequest {
    /// Container ID plus its exact generation.
    pub target: ContainerTarget,
    /// Maximum wait duration. `None` waits until the process terminates.
    pub timeout_ms: Option<u64>,
}

/// Exact exec input passed from durable host orchestration to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverExecRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Exact container generation and caller-selected process identity.
    pub target: ProcessTarget,
    /// Complete validated OCI process configuration.
    pub process: Process,
    /// Host-side standard-I/O disposition for the exec process.
    pub io: ProcessIo,
}

/// Exact per-process signal input passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverSignalProcessRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Exact container generation and process identity.
    pub target: ProcessTarget,
    /// Positive Linux signal delivered unchanged.
    pub signal: Signal,
}

/// Exact per-process wait input passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverWaitProcessRequest {
    /// Exact container generation and process identity.
    pub target: ProcessTarget,
    /// Maximum wait duration. `None` waits until the process terminates.
    pub timeout_ms: Option<u64>,
}

/// Exact captured-output poll passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverReadOutputRequest {
    /// Exact container generation and process identity.
    pub target: ProcessTarget,
    /// Inclusive cursor returned by the previous output chunk.
    pub after_sequence: u64,
    /// Maximum binary payload returned by this call.
    pub max_bytes: u32,
    /// Optional long-poll duration. Omitted means an immediate poll.
    pub wait_timeout_ms: Option<u64>,
}

/// Exact stdin write passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverWriteStdinRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Exact container generation and process identity.
    pub target: ProcessTarget,
    /// Bytes delivered in order with backpressure.
    pub data: Vec<u8>,
}

/// Exact stdin close passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverCloseStdinRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Exact container generation and process identity.
    pub target: ProcessTarget,
}

/// Exact terminal resize passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverResizeRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Exact container generation and process identity.
    pub target: ProcessTarget,
    /// Positive terminal dimensions.
    pub size: TerminalSize,
}

/// Exact pause or resume input passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverContainerOperationRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus its exact generation.
    pub target: ContainerTarget,
}

/// Exact live resource update passed to one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverUpdateRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus its exact generation.
    pub target: ContainerTarget,
    /// Supported OCI Linux resource fields; omitted fields remain unchanged.
    pub resources: LinuxResources,
}

/// Driver-reported process identity returned after exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverProcess {
    pid: i32,
    terminal: bool,
}

impl DriverProcess {
    /// Construct one running process with a positive driver-visible PID.
    pub fn new(pid: i32, terminal: bool) -> Result<Self> {
        if pid <= 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("driver process PID must be positive; received {pid}"),
            )
            .for_operation("construct-driver-process"));
        }
        Ok(Self { pid, terminal })
    }

    /// Positive driver-visible process PID.
    #[must_use]
    pub const fn pid(self) -> i32 {
        self.pid
    }

    /// Whether the driver allocated an OCI terminal for this process.
    #[must_use]
    pub const fn terminal(self) -> bool {
        self.terminal
    }
}

/// Platform executor behind durable OCI lifecycle orchestration.
///
/// Mutating calls must be idempotent by `OperationContext::operation_id`.
/// `create` must prepare the init process without running `process.args`;
/// only `start` may release the configured user program. A retry may arrive
/// after the host process restarted, so implementations must reconcile their
/// platform resources before repeating side effects. A retryable error keeps
/// the host operation active. Before returning a terminal create error, the
/// driver must remove or quarantine all platform resources it allocated;
/// terminal errors from the other mutations must leave a state that can be
/// queried and safely targeted by a later operation.
#[async_trait]
pub trait RuntimeDriver: Send + Sync {
    /// Current availability, maturity, isolation, and probe evidence.
    fn capability(&self) -> DriverCapability;

    /// Runtime operations implemented by this exact driver.
    ///
    /// The five core lifecycle operations are required by the current host
    /// orchestrator. Optional operations must be advertised before the host
    /// exposes or dispatches them.
    fn operations(&self) -> &[RuntimeOperation] {
        &CORE_DRIVER_OPERATIONS
    }

    /// OCI lifecycle hook phases enforced by this exact driver.
    fn hooks(&self) -> &[OciHookPhase] {
        &[]
    }

    /// Versioned create-attachment extensions implemented by this driver.
    fn attachment_capabilities(&self) -> AttachmentCapabilities {
        AttachmentCapabilities::base_v1()
    }

    /// Release driver replay evidence after the Host has durably committed an outcome.
    ///
    /// The Host never invokes this hook for a prepared or retryable operation. Unknown
    /// identities must succeed so replayed Host outcomes and driver/session replacement
    /// can acknowledge the same operation more than once.
    async fn acknowledge_operation(&self, _operation_id: &OperationId) -> Result<()> {
        Ok(())
    }

    /// Reconcile process-local resources with one durable record while the
    /// host service opens.
    ///
    /// Returning an observation asks the host to commit that exact state
    /// before accepting requests. [`DriverRecovery::none`] leaves the durable
    /// record unchanged. Exact init exit evidence may accompany only a stopped
    /// observation. A driver must return no observation when reconciliation
    /// must resume through the original operation, such as an interrupted OCI
    /// `creating` transition.
    /// Implementations must make this hook idempotent because a host failure
    /// may repeat it after the driver-side reconciliation already happened.
    async fn recover(&self, _record: &ContainerRecord) -> Result<DriverRecovery> {
        Ok(DriverRecovery::none())
    }

    /// Resolve a create bundle into driver-owned storage after the durable
    /// generation has been allocated but before any workload resource starts.
    ///
    /// The default keeps the caller's immutable bundle. Drivers implementing
    /// an explicit ownership-handoff extension may atomically relocate it and
    /// return an equivalent bundle with only its host directory changed.
    async fn prepare_create_bundle(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        Ok(request.bundle.clone())
    }

    /// Prepare all OCI create-time resources and return the blocked init PID.
    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState>;

    /// Inspect one exact generation without changing it.
    async fn state(&self, target: ContainerTarget) -> Result<DriverState>;

    /// Release the prepared init process and run the configured program.
    async fn start(&self, request: DriverStartRequest) -> Result<DriverState>;

    /// Deliver exactly the requested signal and return the observed state.
    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState>;

    /// Delete only resources owned by this container generation.
    async fn delete(&self, request: DriverDeleteRequest) -> Result<()>;

    /// Wait for the exact init process and return its stable terminal result.
    async fn wait(&self, _request: DriverWaitRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("wait"))
    }

    /// Execute one exact additional process.
    async fn exec(&self, _request: DriverExecRequest) -> Result<DriverProcess> {
        Err(Error::unsupported("exec"))
    }

    /// Signal one exact init or exec process.
    async fn signal_process(&self, _request: DriverSignalProcessRequest) -> Result<()> {
        Err(Error::unsupported("signal-process"))
    }

    /// Wait for one exact init or exec process.
    async fn wait_process(&self, _request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("wait-process"))
    }

    /// Freeze every process in one exact container generation.
    async fn pause(&self, _request: DriverContainerOperationRequest) -> Result<DriverState> {
        Err(Error::unsupported("pause"))
    }

    /// Thaw every process in one exact container generation.
    async fn resume(&self, _request: DriverContainerOperationRequest) -> Result<DriverState> {
        Err(Error::unsupported("resume"))
    }

    /// List every live init and exec process in one exact generation.
    async fn processes(&self, _target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        Err(Error::unsupported("processes"))
    }

    /// Apply supported live OCI Linux resource changes.
    async fn update(&self, _request: DriverUpdateRequest) -> Result<DriverState> {
        Err(Error::unsupported("update"))
    }

    /// Read normalized resource counters for one exact generation.
    async fn stats(&self, _target: ContainerTarget) -> Result<ContainerStats> {
        Err(Error::unsupported("stats"))
    }

    /// Poll captured stdout and stderr for one exact process.
    async fn read_output(&self, _request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        Err(Error::unsupported("read-output"))
    }

    /// Write bytes to one exact process stdin with backpressure.
    async fn write_stdin(&self, _request: DriverWriteStdinRequest) -> Result<()> {
        Err(Error::unsupported("write-stdin"))
    }

    /// Close one exact process stdin.
    async fn close_stdin(&self, _request: DriverCloseStdinRequest) -> Result<()> {
        Err(Error::unsupported("close-stdin"))
    }

    /// Resize one exact process terminal.
    async fn resize(&self, _request: DriverResizeRequest) -> Result<()> {
        Err(Error::unsupported("resize"))
    }

    /// Upload or download one bounded file through the exact retained root.
    async fn file(&self, _request: FileRequest) -> Result<FileResponse> {
        Err(Error::unsupported("file"))
    }

    /// Inspect or mutate one exact retained container filesystem.
    async fn filesystem(&self, _request: FilesystemRequest) -> Result<FilesystemResponse> {
        Err(Error::unsupported("filesystem"))
    }
}
