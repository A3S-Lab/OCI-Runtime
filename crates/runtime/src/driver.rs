use a3s_oci_core::DriverCapability;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    async_trait, ContainerTarget, DeleteMode, Error, ErrorCode, ExitStatus, IsolationRequest,
    OciBundle, OperationContext, ProcessIo, ProcessTarget, Result, RuntimeOperation, Signal,
};

const CORE_DRIVER_OPERATIONS: [RuntimeOperation; 5] = [
    RuntimeOperation::Create,
    RuntimeOperation::State,
    RuntimeOperation::Start,
    RuntimeOperation::Kill,
    RuntimeOperation::Delete,
];

/// Driver-reported init-process state at one exact container generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverState {
    status: ContainerState,
    pid: Option<i32>,
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
        })
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
}
