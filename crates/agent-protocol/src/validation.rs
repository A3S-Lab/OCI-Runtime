use std::collections::BTreeSet;
use std::path::PathBuf;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerTarget, CreateAttachments, CreateRequest, ErrorCode,
    ExecRequest, IsolationRequest, OciBundle, OutputChunk, ProcessRecord, ProcessTarget,
    ProcessesRequest, ReadOutputRequest, Result, SignalProcessRequest, StatsRequest, UpdateRequest,
    ValidateRequest, WaitProcessRequest,
};

use crate::model::{
    protocol_error, AgentAcknowledgeOperationsRequest, AgentBundle, AgentCloseStdinRequest,
    AgentContainerOperationRequest, AgentCreateRequest, AgentDeleteRequest, AgentExecRequest,
    AgentHello, AgentKillRequest, AgentProcess, AgentProcessExit, AgentProcessSignal,
    AgentProcessesRequest, AgentReadOutputRequest, AgentRequest, AgentResizeRequest, AgentResponse,
    AgentSignalProcessRequest, AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest,
    AgentUpdateRequest, AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest,
    ProtocolRange, RequestEnvelope, ResponseEnvelope, ResponseOutcome,
    AGENT_MAX_ACKNOWLEDGED_OPERATIONS, AGENT_MAX_FRAME_BYTES, AGENT_MAX_IO_PAYLOAD_BYTES,
};

impl AgentAcknowledgeOperationsRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.operation_ids.is_empty() {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "agent operation acknowledgement must contain at least one identity",
            ));
        }
        if self.operation_ids.len() > AGENT_MAX_ACKNOWLEDGED_OPERATIONS {
            return Err(protocol_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "agent operation acknowledgement contains {} identities; maximum is {AGENT_MAX_ACKNOWLEDGED_OPERATIONS}",
                    self.operation_ids.len()
                ),
            ));
        }
        let unique = self.operation_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.operation_ids.len() {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "agent operation acknowledgement contains a duplicate identity",
            ));
        }
        Ok(())
    }
}

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
        let attachments = CreateAttachments::from_bundle(&bundle, self.io.clone())?;
        CreateRequest {
            context: self.context.clone(),
            id: self.target.id.clone(),
            bundle,
            isolation: IsolationRequest::DedicatedVm,
            attachments,
        }
        .validate()
    }
}

impl AgentStateRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)
    }
}

impl AgentWaitRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)
    }
}

impl AgentExecRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(&self.target)?;
        ExecRequest {
            context: self.context.clone(),
            container: self.target.container.clone(),
            process_id: self.target.process_id.clone(),
            process: self.process.clone(),
            io: self.io.clone(),
        }
        .validate()
    }
}

impl AgentSignalProcessRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(&self.target)?;
        SignalProcessRequest {
            context: self.context.clone(),
            process: self.target.clone(),
            signal: self.signal,
        }
        .validate()
    }
}

impl AgentWaitProcessRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(&self.target)?;
        WaitProcessRequest {
            process: self.target.clone(),
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }
}

impl AgentContainerOperationRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)?;
        ContainerOperationRequest {
            context: self.context.clone(),
            target: self.target.clone(),
        }
        .validate()
    }
}

impl AgentProcessesRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)?;
        ProcessesRequest {
            target: self.target.clone(),
        }
        .validate()
    }
}

impl AgentUpdateRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)?;
        UpdateRequest {
            context: self.context.clone(),
            target: self.target.clone(),
            resources: self.resources.clone(),
        }
        .validate()
    }
}

impl AgentStatsRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(&self.target)?;
        StatsRequest {
            target: self.target.clone(),
        }
        .validate()
    }
}

impl AgentReadOutputRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(&self.process)?;
        if self.max_bytes > AGENT_MAX_IO_PAYLOAD_BYTES {
            return Err(protocol_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "agent read-output maxBytes is {}; maximum is \
                     {AGENT_MAX_IO_PAYLOAD_BYTES}",
                    self.max_bytes
                ),
            ));
        }
        ReadOutputRequest {
            process: self.process.clone(),
            after_sequence: self.after_sequence,
            max_bytes: self.max_bytes,
            wait_timeout_ms: self.wait_timeout_ms,
        }
        .validate()
    }
}

impl AgentWriteStdinRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(&self.process)?;
        if self.data.len() > AGENT_MAX_IO_PAYLOAD_BYTES as usize {
            return Err(protocol_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "agent write-stdin payload is {} bytes; maximum is \
                     {AGENT_MAX_IO_PAYLOAD_BYTES}",
                    self.data.len()
                ),
            ));
        }
        Ok(())
    }
}

impl AgentCloseStdinRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(&self.process)
    }
}

impl AgentResizeRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(&self.process)?;
        if self.size.width == 0 || self.size.height == 0 {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "agent resize width and height must both be positive",
            ));
        }
        Ok(())
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
            Self::Wait(request) => request.validate(),
            Self::Exec(request) => request.validate(),
            Self::SignalProcess(request) => request.validate(),
            Self::WaitProcess(request) => request.validate(),
            Self::Pause(request) | Self::Resume(request) => request.validate(),
            Self::Processes(request) => request.validate(),
            Self::Update(request) => request.validate(),
            Self::Stats(request) => request.validate(),
            Self::ReadOutput(request) => request.validate(),
            Self::WriteStdin(request) => request.validate(),
            Self::CloseStdin(request) => request.validate(),
            Self::Resize(request) => request.validate(),
            Self::File(request) => {
                request.validate()?;
                validate_exact_target(&request.target)
            }
            Self::Filesystem(request) => {
                request.validate()?;
                validate_exact_target(&request.target)
            }
            Self::AcknowledgeOperations(request) => request.validate(),
        }
    }

    pub(crate) fn validate_for_protocol(&self, selected_version: u16) -> Result<()> {
        if selected_version < self.minimum_protocol_version() {
            return Err(protocol_error(
                ErrorCode::Unsupported,
                format!(
                    "agent request requires protocol version {}, negotiated {selected_version}",
                    self.minimum_protocol_version()
                ),
            ));
        }
        match self {
            Self::WriteStdin(request) => {
                validate_process_io_context(selected_version, request.context.as_ref())?
            }
            Self::CloseStdin(request) => {
                validate_process_io_context(selected_version, request.context.as_ref())?
            }
            Self::Resize(request) => {
                validate_process_io_context(selected_version, request.context.as_ref())?
            }
            _ => {}
        }
        self.validate()
    }

    const fn minimum_protocol_version(&self) -> u16 {
        match self {
            Self::Create(_) | Self::State(_) | Self::Start(_) | Self::Kill(_) | Self::Delete(_) => {
                1
            }
            Self::Wait(_) => 2,
            Self::Exec(_) | Self::SignalProcess(_) | Self::WaitProcess(_) => 3,
            Self::Pause(_) | Self::Resume(_) | Self::Processes(_) => 4,
            Self::Update(_) | Self::Stats(_) => 5,
            Self::ReadOutput(_) | Self::WriteStdin(_) | Self::CloseStdin(_) => 6,
            Self::Resize(_) => 7,
            Self::File(_) | Self::Filesystem(_) => 9,
            Self::AcknowledgeOperations(_) => 10,
        }
    }
}

fn validate_process_io_context(
    selected_version: u16,
    context: Option<&a3s_oci_sdk::OperationContext>,
) -> Result<()> {
    match (selected_version >= 8, context.is_some()) {
        (true, true) | (false, false) => Ok(()),
        (true, false) => Err(protocol_error(
            ErrorCode::InvalidArgument,
            "agent protocol version 8 process-I/O mutations require operation context",
        )),
        (false, true) => Err(protocol_error(
            ErrorCode::Unsupported,
            "process-I/O operation context requires agent protocol version 8",
        )),
    }
}

impl AgentState {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_target(self.target())?;
        validate_digest(self.config_digest())?;
        match (self.status(), self.pid(), self.paused()) {
            (ContainerState::Created, Some(pid), false) if pid > 0 => Ok(()),
            (ContainerState::Running, Some(pid), _) if pid > 0 => Ok(()),
            (ContainerState::Stopped, None, false) => Ok(()),
            (status, pid, paused) => Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!(
                    "guest returned invalid OCI state {status} with PID {pid:?} and paused={paused}"
                ),
            )),
        }
    }
}

impl AgentProcess {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(self.target())?;
        if self.target().process_id.is_init() {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "exec response cannot use the reserved init process ID",
            ));
        }
        if self.pid() <= 0 {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!("guest returned invalid exec process PID {}", self.pid()),
            ));
        }
        Ok(())
    }
}

impl AgentProcessSignal {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(self.target())
    }
}

impl AgentProcessExit {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_exact_process_target(self.target())?;
        self.status().validate()
    }
}

impl AgentResponse {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::State(state) => state.validate(),
            Self::Deleted => Ok(()),
            Self::ExitStatus(status) => status.validate(),
            Self::Process(process) => process.validate(),
            Self::ProcessSignaled(signal) => signal.validate(),
            Self::ProcessExit(exit) => exit.validate(),
            Self::Processes(processes) => validate_processes(processes),
            Self::Stats(stats) => stats.validate(),
            Self::Output(chunks) => validate_output_chunks(chunks),
            Self::StdinWritten(target)
            | Self::StdinClosed(target)
            | Self::TerminalResized(target) => validate_exact_process_target(target),
            Self::File(response) => validate_exact_target(&response.target),
            Self::Filesystem(response) => validate_exact_target(&response.target),
            Self::OperationsAcknowledged => Ok(()),
        }
    }

    pub(crate) fn validate_for_protocol(&self, selected_version: u16) -> Result<()> {
        let minimum_version = match self {
            Self::State(_) | Self::Deleted => 1,
            Self::ExitStatus(_) => 2,
            Self::Process(_) | Self::ProcessSignaled(_) | Self::ProcessExit(_) => 3,
            Self::Processes(_) => 4,
            Self::Stats(_) => 5,
            Self::Output(_) | Self::StdinWritten(_) | Self::StdinClosed(_) => 6,
            Self::TerminalResized(_) => 7,
            Self::File(_) | Self::Filesystem(_) => 9,
            Self::OperationsAcknowledged => 10,
        };
        if selected_version < minimum_version {
            return Err(protocol_error(
                ErrorCode::Unsupported,
                format!(
                    "agent response requires protocol version {minimum_version}, negotiated \
                     {selected_version}"
                ),
            ));
        }
        self.validate()
    }
}

fn validate_output_chunks(chunks: &[OutputChunk]) -> Result<()> {
    let mut previous: Option<u64> = None;
    let mut total_bytes = 0_u64;
    for chunk in chunks {
        if chunk.sequence == 0 {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "guest output chunks must have strictly increasing positive sequences",
            ));
        }
        if !chunk.eof && chunk.data.is_empty() {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "guest output data chunks must not be empty",
            ));
        }
        if chunk.eof && !chunk.data.is_empty() {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                "guest output EOF chunks must not contain data",
            ));
        }
        if let Some(previous) = previous {
            let width = if chunk.eof {
                1
            } else {
                u64::try_from(chunk.data.len()).map_err(|_| {
                    protocol_error(
                        ErrorCode::ResourceExhausted,
                        "guest output chunk length does not fit its sequence cursor",
                    )
                })?
            };
            let expected = previous.checked_add(width).ok_or_else(|| {
                protocol_error(
                    ErrorCode::ResourceExhausted,
                    "guest output sequence space is exhausted",
                )
            })?;
            if chunk.sequence != expected {
                return Err(protocol_error(
                    ErrorCode::InvalidArgument,
                    "guest output chunks are not byte-cursor contiguous",
                ));
            }
        }
        total_bytes = total_bytes
            .checked_add(chunk.data.len() as u64)
            .ok_or_else(|| {
                protocol_error(
                    ErrorCode::ResourceExhausted,
                    "guest output response byte count overflowed",
                )
            })?;
        previous = Some(chunk.sequence);
    }
    if total_bytes > u64::from(AGENT_MAX_IO_PAYLOAD_BYTES) {
        return Err(protocol_error(
            ErrorCode::ResourceExhausted,
            format!(
                "guest output response contains {total_bytes} bytes; maximum is \
                 {AGENT_MAX_IO_PAYLOAD_BYTES}"
            ),
        ));
    }
    Ok(())
}

fn validate_processes(processes: &[ProcessRecord]) -> Result<()> {
    for (index, process) in processes.iter().enumerate() {
        validate_exact_process_target(&process.target)?;
        if process.pid.is_none_or(|pid| pid == 0) {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!(
                    "guest process inventory returned no live PID for {}",
                    process.target.process_id
                ),
            ));
        }
        if processes[..index]
            .iter()
            .any(|candidate| candidate.target == process.target)
        {
            return Err(protocol_error(
                ErrorCode::InvalidArgument,
                format!(
                    "guest process inventory returned duplicate process {}",
                    process.target.process_id
                ),
            ));
        }
    }
    Ok(())
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
        self.capabilities()
            .validate_for_protocol(self.selected_version())
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
        self.request.validate_for_protocol(selected_version)
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
            response.validate_for_protocol(selected_version)?;
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

fn validate_exact_process_target(target: &ProcessTarget) -> Result<()> {
    validate_exact_target(&target.container)
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
