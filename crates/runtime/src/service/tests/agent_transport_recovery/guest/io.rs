use a3s_oci_agent_protocol::{
    AgentCloseStdinRequest, AgentReadOutputRequest, AgentResizeRequest, AgentWriteStdinRequest,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, OutputChunk, OutputStream, Result};

use super::super::guest_journal::{already_exists, changed_request};
use super::JournaledLifecycleGuest;

impl JournaledLifecycleGuest {
    pub(super) fn read_captured_output(
        &self,
        request: AgentReadOutputRequest,
    ) -> Result<Vec<OutputChunk>> {
        const OUTPUT: &[u8] = b"ready\n";

        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.read_output_requests += 1;
        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-read-output")
        })?;
        if current.target() != &request.process.container
            || (!request.process.process_id.is_init()
                && journal
                    .exec
                    .entry
                    .as_ref()
                    .is_none_or(|(_, process)| process.target() != &request.process))
        {
            return Err(
                Error::new(ErrorCode::NotFound, "guest process is unavailable")
                    .for_operation("agent-read-output"),
            );
        }

        let latest = OUTPUT.len() as u64 + 1;
        if request.after_sequence > latest {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "guest output cursor is ahead of the stream",
            )
            .for_operation("agent-read-output"));
        }
        let mut chunks = Vec::new();
        let mut cursor = request.after_sequence;
        if cursor < OUTPUT.len() as u64 {
            let offset = cursor as usize;
            let length = (request.max_bytes as usize).min(OUTPUT.len() - offset);
            if length > 0 {
                cursor += length as u64;
                chunks.push(OutputChunk {
                    sequence: cursor,
                    stream: OutputStream::Stdout,
                    data: OUTPUT[offset..offset + length].to_vec(),
                    eof: false,
                });
            }
        }
        if cursor == OUTPUT.len() as u64 {
            chunks.push(OutputChunk {
                sequence: latest,
                stream: OutputStream::Stdout,
                data: Vec::new(),
                eof: true,
            });
        }
        Ok(chunks)
    }

    pub(super) fn write_to_stdin(&self, request: AgentWriteStdinRequest) -> Result<()> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.write_stdin.requests += 1;
        let operation_id = request
            .context
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "guest stdin write requires an operation context",
                )
                .for_operation("agent-write-stdin")
            })?
            .operation_id
            .clone();
        if let Some((recorded, ())) = journal.write_stdin.entry.as_ref() {
            let recorded_operation_id = &recorded
                .context
                .as_ref()
                .expect("recorded stdin write context")
                .operation_id;
            if recorded_operation_id == &operation_id {
                if recorded != &request {
                    return Err(changed_request("write-stdin"));
                }
                return Ok(());
            }
            return Err(already_exists("write-stdin"));
        }

        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-write-stdin")
        })?;
        if current.target() != &request.process.container {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-write-stdin"));
        }
        if current.status() != ContainerState::Running {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest stdin write requires a running container",
            )
            .for_operation("agent-write-stdin"));
        }
        if !request.process.process_id.is_init()
            && journal
                .exec
                .entry
                .as_ref()
                .is_none_or(|(_, process)| process.target() != &request.process)
        {
            return Err(
                Error::new(ErrorCode::NotFound, "guest process is unavailable")
                    .for_operation("agent-write-stdin"),
            );
        }

        journal.write_stdin.effects += 1;
        journal.write_stdin.entry = Some((request, ()));
        Ok(())
    }

    pub(in super::super) fn recorded_write_stdin_request(&self) -> Option<AgentWriteStdinRequest> {
        self.journal
            .lock()
            .expect("guest journal lock")
            .write_stdin
            .entry
            .as_ref()
            .map(|(request, ())| request.clone())
    }

    pub(super) fn close_process_stdin(&self, request: AgentCloseStdinRequest) -> Result<()> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.close_stdin.requests += 1;
        let operation_id = request
            .context
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "guest stdin close requires an operation context",
                )
                .for_operation("agent-close-stdin")
            })?
            .operation_id
            .clone();
        if let Some((recorded, ())) = journal.close_stdin.entry.as_ref() {
            let recorded_operation_id = &recorded
                .context
                .as_ref()
                .expect("recorded stdin close context")
                .operation_id;
            if recorded_operation_id == &operation_id {
                if recorded != &request {
                    return Err(changed_request("close-stdin"));
                }
                return Ok(());
            }
            return Err(already_exists("close-stdin"));
        }

        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-close-stdin")
        })?;
        if current.target() != &request.process.container {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-close-stdin"));
        }
        if !request.process.process_id.is_init()
            && journal
                .exec
                .entry
                .as_ref()
                .is_none_or(|(_, process)| process.target() != &request.process)
        {
            return Err(
                Error::new(ErrorCode::NotFound, "guest process is unavailable")
                    .for_operation("agent-close-stdin"),
            );
        }

        journal.close_stdin.effects += 1;
        journal.close_stdin.entry = Some((request, ()));
        Ok(())
    }

    pub(in super::super) fn recorded_close_stdin_request(&self) -> Option<AgentCloseStdinRequest> {
        self.journal
            .lock()
            .expect("guest journal lock")
            .close_stdin
            .entry
            .as_ref()
            .map(|(request, ())| request.clone())
    }

    pub(super) fn resize_terminal(&self, request: AgentResizeRequest) -> Result<()> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.resize.requests += 1;
        let operation_id = request
            .context
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "guest terminal resize requires an operation context",
                )
                .for_operation("agent-resize")
            })?
            .operation_id
            .clone();
        if let Some((recorded, ())) = journal.resize.entry.as_ref() {
            let recorded_operation_id = &recorded
                .context
                .as_ref()
                .expect("recorded terminal resize context")
                .operation_id;
            if recorded_operation_id == &operation_id {
                if recorded != &request {
                    return Err(changed_request("resize"));
                }
                return Ok(());
            }
            return Err(already_exists("resize"));
        }

        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-resize")
        })?;
        if current.target() != &request.process.container {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-resize"));
        }
        if current.status() == ContainerState::Stopped {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest terminal process has already exited",
            )
            .for_operation("agent-resize"));
        }
        if !request.process.process_id.is_init()
            && journal
                .exec
                .entry
                .as_ref()
                .is_none_or(|(_, process)| process.target() != &request.process)
        {
            return Err(
                Error::new(ErrorCode::NotFound, "guest process is unavailable")
                    .for_operation("agent-resize"),
            );
        }

        journal.resize.effects += 1;
        journal.resize.entry = Some((request, ()));
        Ok(())
    }

    pub(in super::super) fn recorded_resize_request(&self) -> Option<AgentResizeRequest> {
        self.journal
            .lock()
            .expect("guest journal lock")
            .resize
            .entry
            .as_ref()
            .map(|(request, ())| request.clone())
    }
}
