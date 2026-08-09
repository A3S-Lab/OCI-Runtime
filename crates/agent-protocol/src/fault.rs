use std::fmt;

use a3s_oci_sdk::{OperationId, Result};
use serde::{Deserialize, Serialize};

use crate::AgentOperation;

/// One host/guest operation transition that qualification can fault-inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

    /// Stable name used in retained qualification reports and CLI arguments.
    pub const fn as_str(self) -> &'static str {
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

    /// Whether this transition is observed by the host-side client.
    #[must_use]
    pub const fn is_host(self) -> bool {
        matches!(
            self,
            Self::HostBeforeRequestWrite
                | Self::HostAfterRequestWrite
                | Self::HostBeforeResponseRead
                | Self::HostAfterResponseRead
        )
    }

    /// Whether this transition is observed by the guest-side server.
    #[must_use]
    pub const fn is_guest(self) -> bool {
        matches!(
            self,
            Self::GuestAfterRequestRead
                | Self::GuestBeforeDispatch
                | Self::GuestAfterDispatch
                | Self::GuestBeforeResponseWrite
                | Self::GuestAfterResponseWrite
        )
    }
}

/// Clone-wide host shutdown transitions exposed to qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

    /// Stable name used in retained qualification reports and CLI arguments.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostBeforeShutdown => "host-before-shutdown",
            Self::HostAfterShutdown => "host-after-shutdown",
        }
    }
}

/// Operation or shutdown transition selected for transport qualification.
///
/// The untagged wire form retains the stable kebab-case stage name used by
/// CLI arguments and machine-readable evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentTransportFaultStage {
    /// One request/response transition.
    Operation(AgentTransportOperationStage),
    /// One explicit clone-wide Host shutdown transition.
    Shutdown(AgentTransportShutdownStage),
}

impl AgentTransportFaultStage {
    /// Complete qualification registry: nine operation transitions and two
    /// explicit Host shutdown transitions.
    pub const ALL: [Self; 11] = [
        Self::Operation(AgentTransportOperationStage::HostBeforeRequestWrite),
        Self::Operation(AgentTransportOperationStage::HostAfterRequestWrite),
        Self::Operation(AgentTransportOperationStage::HostBeforeResponseRead),
        Self::Operation(AgentTransportOperationStage::HostAfterResponseRead),
        Self::Operation(AgentTransportOperationStage::GuestAfterRequestRead),
        Self::Operation(AgentTransportOperationStage::GuestBeforeDispatch),
        Self::Operation(AgentTransportOperationStage::GuestAfterDispatch),
        Self::Operation(AgentTransportOperationStage::GuestBeforeResponseWrite),
        Self::Operation(AgentTransportOperationStage::GuestAfterResponseWrite),
        Self::Shutdown(AgentTransportShutdownStage::HostBeforeShutdown),
        Self::Shutdown(AgentTransportShutdownStage::HostAfterShutdown),
    ];

    /// Stable name used by retained qualification reports and CLI arguments.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operation(stage) => stage.as_str(),
            Self::Shutdown(stage) => stage.as_str(),
        }
    }

    /// Return the request/response transition, when one was selected.
    pub const fn operation(self) -> Option<AgentTransportOperationStage> {
        match self {
            Self::Operation(stage) => Some(stage),
            Self::Shutdown(_) => None,
        }
    }

    /// Return the shutdown transition, when one was selected.
    pub const fn shutdown(self) -> Option<AgentTransportShutdownStage> {
        match self {
            Self::Operation(_) => None,
            Self::Shutdown(stage) => Some(stage),
        }
    }

    /// Whether this transition is observed by the Host client.
    #[must_use]
    pub const fn is_host(self) -> bool {
        match self {
            Self::Operation(stage) => stage.is_host(),
            Self::Shutdown(_) => true,
        }
    }

    /// Whether this transition is observed by the Guest server.
    #[must_use]
    pub const fn is_guest(self) -> bool {
        matches!(self, Self::Operation(stage) if stage.is_guest())
    }
}

impl From<AgentTransportOperationStage> for AgentTransportFaultStage {
    fn from(stage: AgentTransportOperationStage) -> Self {
        Self::Operation(stage)
    }
}

impl From<AgentTransportShutdownStage> for AgentTransportFaultStage {
    fn from(stage: AgentTransportShutdownStage) -> Self {
        Self::Shutdown(stage)
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

    /// Check a guest transition after the complete request has validated, with
    /// its idempotency identity when the operation carries one.
    ///
    /// Existing injectors remain operation-stage based. Real-VM guest
    /// qualification overrides this hook so an unrelated request cannot cross
    /// an armed transition.
    fn check_operation(
        &self,
        point: AgentTransportFaultPoint,
        operation_id: Option<&OperationId>,
    ) -> Result<()> {
        let _ = operation_id;
        self.check(point)
    }
}

/// Non-configurable production fault injector.
#[derive(Debug, Default)]
pub struct NoAgentTransportFaultInjector;

impl AgentTransportFaultInjector for NoAgentTransportFaultInjector {
    fn check(&self, _point: AgentTransportFaultPoint) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentTransportFaultStage, AgentTransportOperationStage, AgentTransportShutdownStage,
    };

    #[test]
    fn combined_stage_registry_round_trips_stable_names() {
        assert_eq!(AgentTransportFaultStage::ALL.len(), 11);
        let expected = AgentTransportOperationStage::ALL
            .into_iter()
            .map(AgentTransportFaultStage::from)
            .chain(
                AgentTransportShutdownStage::ALL
                    .into_iter()
                    .map(AgentTransportFaultStage::from),
            )
            .collect::<Vec<_>>();
        assert_eq!(AgentTransportFaultStage::ALL.as_slice(), expected);
        for stage in AgentTransportFaultStage::ALL {
            let encoded = serde_json::to_string(&stage).expect("serialize transport stage");
            assert_eq!(encoded, format!("\"{}\"", stage.as_str()));
            let decoded: AgentTransportFaultStage =
                serde_json::from_str(&encoded).expect("deserialize transport stage");
            assert_eq!(decoded, stage);
        }
        assert_eq!(
            AgentTransportFaultStage::from(AgentTransportOperationStage::GuestAfterResponseWrite)
                .operation(),
            Some(AgentTransportOperationStage::GuestAfterResponseWrite)
        );
        assert_eq!(
            AgentTransportFaultStage::from(AgentTransportShutdownStage::HostAfterShutdown)
                .shutdown(),
            Some(AgentTransportShutdownStage::HostAfterShutdown)
        );
    }
}
