use std::fmt;

use a3s_oci_sdk::Result;

use crate::AgentOperation;

/// One host/guest operation transition that qualification can fault-inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentTransportOperationStage {
    /// Host has not started writing the request frame.
    HostBeforeRequestWrite,
    /// Host has completely written the request frame.
    HostAfterRequestWrite,
    /// Host has not started reading the response frame.
    HostBeforeResponseRead,
    /// Host has completely read the response frame.
    HostAfterResponseRead,
    /// Guest has read and validated the request frame.
    GuestAfterRequestRead,
    /// Guest has not called the service implementation.
    GuestBeforeDispatch,
    /// Guest service dispatch has completed with success or failure.
    GuestAfterDispatch,
    /// Guest has not started writing the response frame.
    GuestBeforeResponseWrite,
    /// Guest has completely written the response frame.
    GuestAfterResponseWrite,
}

impl AgentTransportOperationStage {
    /// Complete transition registry. Fault matrices iterate this list so a
    /// newly added stage cannot silently escape qualification.
    pub const ALL: [Self; 9] = [
        Self::HostBeforeRequestWrite,
        Self::HostAfterRequestWrite,
        Self::HostBeforeResponseRead,
        Self::HostAfterResponseRead,
        Self::GuestAfterRequestRead,
        Self::GuestBeforeDispatch,
        Self::GuestAfterDispatch,
        Self::GuestBeforeResponseWrite,
        Self::GuestAfterResponseWrite,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::HostBeforeRequestWrite => "host-before-request-write",
            Self::HostAfterRequestWrite => "host-after-request-write",
            Self::HostBeforeResponseRead => "host-before-response-read",
            Self::HostAfterResponseRead => "host-after-response-read",
            Self::GuestAfterRequestRead => "guest-after-request-read",
            Self::GuestBeforeDispatch => "guest-before-dispatch",
            Self::GuestAfterDispatch => "guest-after-dispatch",
            Self::GuestBeforeResponseWrite => "guest-before-response-write",
            Self::GuestAfterResponseWrite => "guest-after-response-write",
        }
    }
}

/// Clone-wide host shutdown transitions exposed to qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentTransportShutdownStage {
    /// Host has removed the stream from clone-shared ownership but has not
    /// requested an orderly transport shutdown.
    HostBeforeShutdown,
    /// Host has attempted orderly transport shutdown and is about to release
    /// the stream.
    HostAfterShutdown,
}

impl AgentTransportShutdownStage {
    /// Complete shutdown transition registry.
    pub const ALL: [Self; 2] = [Self::HostBeforeShutdown, Self::HostAfterShutdown];

    const fn as_str(self) -> &'static str {
        match self {
            Self::HostBeforeShutdown => "host-before-shutdown",
            Self::HostAfterShutdown => "host-after-shutdown",
        }
    }
}

/// Exact negotiated protocol boundary presented to a fault injector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentTransportFaultPoint {
    /// One request/response transition for an exact operation.
    Operation {
        /// Negotiated protocol version carried by this connection.
        protocol_version: u16,
        /// Operation carried by the request.
        operation: AgentOperation,
        /// Ordered request/response transition.
        stage: AgentTransportOperationStage,
    },
    /// One explicit host shutdown transition.
    Shutdown {
        /// Negotiated protocol version carried by this connection.
        protocol_version: u16,
        /// Ordered shutdown transition.
        stage: AgentTransportShutdownStage,
    },
}

impl fmt::Display for AgentTransportFaultPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation {
                protocol_version,
                operation,
                stage,
            } => write!(
                formatter,
                "agent-v{protocol_version}.{}-{}",
                operation.as_str(),
                stage.as_str()
            ),
            Self::Shutdown {
                protocol_version,
                stage,
            } => write!(formatter, "agent-v{protocol_version}.{}", stage.as_str()),
        }
    }
}

/// Qualification hook for deterministic transport interruption.
///
/// Production entry points install [`NoAgentTransportFaultInjector`]. Test and
/// real-host qualification paths may explicitly provide another implementation
/// to fail one exact negotiated operation transition.
pub trait AgentTransportFaultInjector: fmt::Debug + Send + Sync {
    /// Return an injected error at `point`, or allow the transition to proceed.
    fn check(&self, point: AgentTransportFaultPoint) -> Result<()>;
}

/// Non-configurable production fault injector.
#[derive(Debug, Default)]
pub struct NoAgentTransportFaultInjector;

impl AgentTransportFaultInjector for NoAgentTransportFaultInjector {
    fn check(&self, _point: AgentTransportFaultPoint) -> Result<()> {
        Ok(())
    }
}
