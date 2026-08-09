use a3s_oci_agent_protocol::AgentReadOutputRequest;
use a3s_oci_sdk::{Error, ErrorCode, OutputChunk, OutputStream, Result};

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
}
