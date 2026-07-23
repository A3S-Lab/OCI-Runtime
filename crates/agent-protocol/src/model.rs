use std::fmt;
use std::path::PathBuf;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, Error, ErrorCode, OciBundle, OperationContext, ProcessIo, Result,
    Signal,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Oldest host-to-guest protocol version implemented by this build.
pub const AGENT_PROTOCOL_VERSION_MIN: u16 = 1;
/// Newest host-to-guest protocol version implemented by this build.
pub const AGENT_PROTOCOL_VERSION_MAX: u16 = 1;
/// Maximum encoded host-to-guest frame size.
pub const AGENT_MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;
/// Required session-token entropy supplied by the host.
pub const AGENT_SESSION_TOKEN_BYTES: usize = 32;

const MAX_GUEST_PATH_BYTES: usize = 4_096;
const MAX_CAPABILITY_TEXT_BYTES: usize = 128;

/// Secret provisioned independently to both endpoints before connection.
///
/// Debug formatting is deliberately redacted. The host must fill the 32-byte
/// value from its operating-system CSPRNG and transfer it to the guest through
/// a protected bootstrap channel.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken([u8; AGENT_SESSION_TOKEN_BYTES]);

impl SessionToken {
    /// Construct a token from 256 bits supplied by the host CSPRNG.
    pub fn from_bytes(bytes: [u8; AGENT_SESSION_TOKEN_BYTES]) -> Result<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "agent session token must not be all zero",
            )
            .for_operation("construct-agent-session-token"));
        }
        Ok(Self(bytes))
    }

    /// Borrow the secret bytes for protected bootstrap transport.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AGENT_SESSION_TOKEN_BYTES] {
        &self.0
    }

    pub(crate) fn matches(&self, candidate: &Self) -> bool {
        self.0
            .iter()
            .zip(candidate.0.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken([REDACTED])")
    }
}

impl Serialize for SessionToken {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = String::with_capacity(AGENT_SESSION_TOKEN_BYTES * 2);
        for byte in self.0 {
            use fmt::Write;
            write!(&mut encoded, "{byte:02x}").map_err(serde::ser::Error::custom)?;
        }
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SessionToken {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != AGENT_SESSION_TOKEN_BYTES * 2
            || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(de::Error::custom(
                "agent session token must contain exactly 64 hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; AGENT_SESSION_TOKEN_BYTES];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .map_err(de::Error::custom)?;
        }
        Self::from_bytes(bytes).map_err(de::Error::custom)
    }
}

/// Absolute normalized path inside the Linux guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct GuestPath(String);

impl GuestPath {
    /// Validate an absolute guest path without applying host path semantics.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_guest_path(&value)?;
        Ok(Self(value))
    }

    /// Borrow the normalized Linux path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to a native path. This is intended for the Linux guest.
    #[must_use]
    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(&self.0)
    }
}

impl<'de> Deserialize<'de> for GuestPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Exact OCI configuration snapshot plus its guest-visible bundle directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentBundle {
    guest_directory: GuestPath,
    config_digest: String,
    config_json: String,
}

impl AgentBundle {
    /// Copy the immutable SDK bundle into a guest request.
    #[must_use]
    pub fn new(bundle: &OciBundle, guest_directory: GuestPath) -> Self {
        Self {
            guest_directory,
            config_digest: bundle.config_digest().to_string(),
            config_json: bundle.config_json().to_string(),
        }
    }

    /// Guest-visible absolute bundle directory.
    #[must_use]
    pub const fn guest_directory(&self) -> &GuestPath {
        &self.guest_directory
    }

    /// SHA-256 digest of the exact configuration text.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Exact accepted `config.json` text.
    #[must_use]
    pub fn config_json(&self) -> &str {
        &self.config_json
    }

    /// Reconstruct and fully validate the bundle on the Linux guest.
    pub fn to_guest_bundle(&self) -> Result<OciBundle> {
        let bundle =
            OciBundle::from_json(self.guest_directory.to_path_buf(), self.config_json.clone())?;
        if bundle.config_digest() != self.config_digest {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "agent bundle digest mismatch: calculated {}, received {}",
                    bundle.config_digest(),
                    self.config_digest
                ),
            )
            .for_operation("decode-agent-bundle"));
        }
        Ok(bundle)
    }
}

/// Guest operations available in protocol version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentOperation {
    Create,
    State,
    Start,
    Kill,
    Delete,
}

/// Runtime properties reported by the guest during negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCapabilities {
    agent_version: String,
    architecture: String,
    operations: Vec<AgentOperation>,
    max_frame_bytes: u32,
}

impl AgentCapabilities {
    /// Construct a protocol-v1 capability report.
    pub fn core(agent_version: impl Into<String>, architecture: impl Into<String>) -> Result<Self> {
        let capabilities = Self {
            agent_version: agent_version.into(),
            architecture: architecture.into(),
            operations: vec![
                AgentOperation::Create,
                AgentOperation::State,
                AgentOperation::Start,
                AgentOperation::Kill,
                AgentOperation::Delete,
            ],
            max_frame_bytes: AGENT_MAX_FRAME_BYTES,
        };
        capabilities.validate()?;
        Ok(capabilities)
    }

    /// Guest-agent package version.
    #[must_use]
    pub fn agent_version(&self) -> &str {
        &self.agent_version
    }

    /// Guest CPU architecture.
    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Exactly the operations accepted by this guest.
    #[must_use]
    pub fn operations(&self) -> &[AgentOperation] {
        &self.operations
    }

    /// Maximum frame size accepted by this guest.
    #[must_use]
    pub const fn max_frame_bytes(&self) -> u32 {
        self.max_frame_bytes
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_capability_text("agentVersion", &self.agent_version)?;
        validate_capability_text("architecture", &self.architecture)?;
        if self.operations.is_empty() {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "guest advertises no agent operations",
            ));
        }
        for (index, operation) in self.operations.iter().enumerate() {
            if self.operations[..index].contains(operation) {
                return Err(protocol_error(
                    ErrorCode::InvalidArgument,
                    format!("guest advertises duplicate operation {operation:?}"),
                ));
            }
        }
        if self.max_frame_bytes != AGENT_MAX_FRAME_BYTES {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!("protocol v1 requires maxFrameBytes={AGENT_MAX_FRAME_BYTES}"),
            ));
        }
        Ok(())
    }
}

/// Successful protocol negotiation details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentHello {
    selected_version: u16,
    capabilities: AgentCapabilities,
}

impl AgentHello {
    pub(crate) fn new(selected_version: u16, capabilities: AgentCapabilities) -> Self {
        Self {
            selected_version,
            capabilities,
        }
    }

    /// Negotiated protocol version.
    #[must_use]
    pub const fn selected_version(&self) -> u16 {
        self.selected_version
    }

    /// Validated guest capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> &AgentCapabilities {
        &self.capabilities
    }
}

/// OCI create input sent to the guest executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCreateRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus a positive exact generation.
    pub target: ContainerTarget,
    /// Immutable configuration and guest-visible bundle path.
    pub bundle: AgentBundle,
    /// Requested init-process standard-I/O disposition.
    pub io: ProcessIo,
}

/// OCI state query sent to the guest executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentStateRequest {
    /// Container ID plus a positive exact generation.
    pub target: ContainerTarget,
}

/// OCI start input sent to the guest executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentStartRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus a positive exact generation.
    pub target: ContainerTarget,
    /// Digest that must match the guest's create-time snapshot.
    pub expected_config_digest: String,
}

/// OCI signal input sent to the guest executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentKillRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus a positive exact generation.
    pub target: ContainerTarget,
    /// Positive Linux signal number delivered unchanged.
    pub signal: Signal,
    /// Whether the signal applies to every process in the container.
    pub all: bool,
}

/// OCI cleanup input sent to the guest executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDeleteRequest {
    /// Stable idempotency and deadline metadata.
    pub context: OperationContext,
    /// Container ID plus a positive exact generation.
    pub target: ContainerTarget,
    /// Stopped-only or force cleanup behavior.
    pub mode: DeleteMode,
}

/// One host request after negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "kebab-case")]
pub enum AgentRequest {
    Create(AgentCreateRequest),
    State(AgentStateRequest),
    Start(AgentStartRequest),
    Kill(AgentKillRequest),
    Delete(AgentDeleteRequest),
}

/// Guest-observed init-process state for one exact generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentState {
    target: ContainerTarget,
    status: ContainerState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<i32>,
    config_digest: String,
}

impl AgentState {
    /// Construct a state report and enforce its status/PID invariants.
    pub fn new(
        target: ContainerTarget,
        status: ContainerState,
        pid: Option<i32>,
        config_digest: impl Into<String>,
    ) -> Result<Self> {
        let state = Self {
            target,
            status,
            pid,
            config_digest: config_digest.into(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Exact container generation observed by the guest.
    #[must_use]
    pub const fn target(&self) -> &ContainerTarget {
        &self.target
    }

    /// OCI lifecycle state observed by the guest.
    #[must_use]
    pub const fn status(&self) -> ContainerState {
        self.status
    }

    /// Positive guest init PID while the process exists.
    #[must_use]
    pub const fn pid(&self) -> Option<i32> {
        self.pid
    }

    /// Digest of the immutable configuration owned by this generation.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }
}

/// Successful guest response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "value", rename_all = "kebab-case")]
pub enum AgentResponse {
    State(AgentState),
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProtocolRange {
    pub min: u16,
    pub max: u16,
}

impl ProtocolRange {
    pub const CURRENT: Self = Self {
        min: AGENT_PROTOCOL_VERSION_MIN,
        max: AGENT_PROTOCOL_VERSION_MAX,
    };

    pub(crate) fn validate(self) -> Result<()> {
        if self.min == 0 || self.min > self.max {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!("invalid agent protocol range {}..={}", self.min, self.max),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HostHello {
    pub protocols: ProtocolRange,
    pub token: SessionToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum HelloOutcome {
    Accepted { hello: AgentHello },
    Rejected { error: Error },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestEnvelope {
    pub version: u16,
    pub request_id: u64,
    pub request: AgentRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum ResponseOutcome {
    Succeeded { response: AgentResponse },
    Failed { error: Error },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResponseEnvelope {
    pub version: u16,
    pub request_id: u64,
    pub outcome: ResponseOutcome,
}

pub(crate) fn protocol_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("agent-protocol")
}

fn validate_guest_path(value: &str) -> Result<()> {
    if value.is_empty()
        || !value.starts_with('/')
        || value.len() > MAX_GUEST_PATH_BYTES
        || value.as_bytes().contains(&0)
        || value.contains('\\')
    {
        return Err(protocol_error(
            ErrorCode::InvalidArgument,
            "guest path must be an absolute Linux path of at most 4096 bytes",
        ));
    }
    if value == "/" {
        return Ok(());
    }
    if value != "/" && value.ends_with('/') {
        return Err(protocol_error(
            ErrorCode::InvalidArgument,
            "guest path must not contain a trailing separator",
        ));
    }
    if value
        .split('/')
        .skip(1)
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(protocol_error(
            ErrorCode::InvalidArgument,
            "guest path must be normalized and must not contain dot components",
        ));
    }
    Ok(())
}

fn validate_capability_text(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CAPABILITY_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(protocol_error(
            ErrorCode::InvalidArgument,
            format!("{field} must contain 1..={MAX_CAPABILITY_TEXT_BYTES} printable bytes"),
        ));
    }
    Ok(())
}
