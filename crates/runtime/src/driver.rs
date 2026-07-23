use a3s_oci_core::DriverCapability;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerTarget, DeleteMode, Error, ErrorCode, IsolationRequest, OciBundle,
    OperationContext, ProcessIo, Result, Signal,
};

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
}
