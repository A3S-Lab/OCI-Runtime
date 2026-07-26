//! Versioned, bounded host-to-guest protocol for OCI lifecycle execution.
//!
//! The Windows WHPX, Linux KVM, and macOS HVF drivers use the same messages.
//! Platform transports provide one authenticated byte stream; this crate owns
//! negotiation, framing, validation, correlation, and typed dispatch.

mod client;
mod inherited_descriptor;
mod model;
mod server;
mod transport;
mod validation;
mod wire;

pub use client::AgentClient;
pub use inherited_descriptor::{
    AgentInheritedDescriptorRole, AgentInheritedDescriptorSchema, AgentInheritedDescriptorSlot,
    AgentInheritedDescriptorType,
};
pub use model::{
    AgentBundle, AgentCapabilities, AgentCloseStdinRequest, AgentContainerOperationRequest,
    AgentCreateRequest, AgentDeleteRequest, AgentExecRequest, AgentHello, AgentKillRequest,
    AgentOperation, AgentProcess, AgentProcessExit, AgentProcessSignal, AgentProcessesRequest,
    AgentReadOutputRequest, AgentRequest, AgentResizeRequest, AgentResponse,
    AgentSignalProcessRequest, AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest,
    AgentUpdateRequest, AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest,
    GuestPath, SessionToken, AGENT_MAX_FRAME_BYTES, AGENT_MAX_IO_PAYLOAD_BYTES,
    AGENT_PROTOCOL_VERSION_MAX, AGENT_PROTOCOL_VERSION_MIN, AGENT_SESSION_TOKEN_BYTES,
    AGENT_SESSION_TOKEN_ENV,
};
pub use server::{serve_agent_connection, GuestAgentService};
pub use transport::{AgentVsockEndpoint, AGENT_VSOCK_PORT};

#[cfg(test)]
mod tests;
