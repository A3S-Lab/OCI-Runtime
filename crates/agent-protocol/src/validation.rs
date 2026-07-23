use std::path::PathBuf;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, ErrorCode, IsolationRequest, OciBundle, Result, ValidateRequest,
};

use crate::model::{
    protocol_error, AgentBundle, AgentCreateRequest, AgentDeleteRequest, AgentHello,
    AgentKillRequest, AgentRequest, AgentResponse, AgentStartRequest, AgentState,
    AgentStateRequest, ProtocolRange, RequestEnvelope, ResponseEnvelope, ResponseOutcome,
    AGENT_MAX_FRAME_BYTES,
};

impl AgentBundle {
    pub(crate) fn validate(&self) -> Result<OciBundle> {
        let bundle = OciBundle::from_json(validation_directory(), self.config_json().to_string())?;
        if bundle.config_digest() != self.config_digest() {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!(
                    "agent bundle digest mismatch: calculated {}, received {}",
                    bundle.config_digest(),
                    self.config_digest()
                ),
            ));
        }
        Ok(bundle)
    }
}

impl AgentCreateRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)?;
        let bundle = self.bundle.validate()?;
        CreateRequest {
            context: self.context.clone(),
            id: self.target.id.clone(),
            bundle,
            isolation: IsolationRequest::DedicatedVm,
            io: self.io.clone(),
        }
        .validate()
    }
}

impl AgentStateRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)
    }
}

impl AgentStartRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)?;
        validate_digest(&self.expected_config_digest)
    }
}

impl AgentKillRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)
    }
}

impl AgentDeleteRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)
    }
}

impl AgentRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Create(request) => request.validate(),
            Self::State(request) => request.validate(),
            Self::Start(request) => request.validate(),
            Self::Kill(request) => request.validate(),
            Self::Delete(request) => request.validate(),
        }
    }
}

impl AgentState {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(self.target())?;
        validate_digest(self.config_digest())?;
        match (self.status(), self.pid()) {
            (ContainerState::Created | ContainerState::Running, Some(pid)) if pid > 0 => Ok(()),
            (ContainerState::Stopped, None) => Ok(()),
            (status, pid) => Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!("guest returned invalid OCI state {status} with PID {pid:?}"),
            )),
        }
    }
}

impl AgentResponse {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::State(state) => state.validate(),
            Self::Deleted => Ok(()),
        }
    }
}

impl AgentHello {
    pub(crate) fn validate(&self, requested: ProtocolRange) -> Result<()> {
        requested.validate()?;
        if self.selected_version() < requested.min
            || self.selected_version() > requested.max
            || self.selected_version() < crate::AGENT_PROTOCOL_VERSION_MIN
            || self.selected_version() > crate::AGENT_PROTOCOL_VERSION_MAX
        {
            return Err(protocol_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "guest selected unsupported agent protocol version {}",
                    self.selected_version()
                ),
            ));
        }
        self.capabilities().validate()
    }
}

impl RequestEnvelope {
    pub(crate) fn validate(&self, selected_version: u16) -> Result<()> {
        if self.version != selected_version {
            return Err(protocol_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "agent request version {} does not match negotiated version {selected_version}",
                    self.version
                ),
            ));
        }
        if self.request_id == 0 {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "agent request ID zero is reserved",
            ));
        }
        self.request.validate()
    }
}

impl ResponseEnvelope {
    pub(crate) fn validate(&self, selected_version: u16, expected_request_id: u64) -> Result<()> {
        if self.version != selected_version {
            return Err(protocol_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "agent response version {} does not match negotiated version {selected_version}",
                    self.version
                ),
            ));
        }
        if self.request_id != expected_request_id {
            return Err(protocol_error(
                ErrorCode::Conflict,
                format!(
                    "agent response ID {} does not match request ID {expected_request_id}",
                    self.request_id
                ),
            ));
        }
        if let ResponseOutcome::Succeeded { response } = &self.outcome {
            response.validate()?;
        }
        Ok(())
    }
}

pub(crate) fn negotiate_protocol(host: ProtocolRange) -> Result<u16> {
    host.validate()?;
    let minimum = host.min.max(crate::AGENT_PROTOCOL_VERSION_MIN);
    let maximum = host.max.min(crate::AGENT_PROTOCOL_VERSION_MAX);
    if minimum > maximum {
        return Err(protocol_error(
            ErrorCode::FailedPrecondition,
            format!(
                "no common agent protocol version: host {}..={}, guest {}..={}",
                host.min,
                host.max,
                crate::AGENT_PROTOCOL_VERSION_MIN,
                crate::AGENT_PROTOCOL_VERSION_MAX
            ),
        ));
    }
    Ok(maximum)
}

fn validate_exact_target(target: &ContainerTarget) -> Result<()> {
    match target.generation {
        Some(generation) if generation.0 > 0 => Ok(()),
        _ => Err(protocol_error(
            ErrorCode::InvalidArgument,
            format!(
                "guest request for container {} must carry a positive exact generation",
                target.id
            ),
        )),
    }
}

fn validate_digest(value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid_digest());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_digest());
    }
    Ok(())
}

fn invalid_digest() -> a3s_oci_sdk::Error {
    protocol_error(
        ErrorCode::InvalidArgument,
        "configuration digest must be canonical lowercase sha256:<64 hex>",
    )
}

fn validation_directory() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\a3s-agent-protocol-validation")
    }

    #[cfg(not(windows))]
    {
        PathBuf::from("/a3s-agent-protocol-validation")
    }
}

const _: () = assert!(AGENT_MAX_FRAME_BYTES > a3s_oci_sdk::MAX_CONFIG_BYTES as u32);
