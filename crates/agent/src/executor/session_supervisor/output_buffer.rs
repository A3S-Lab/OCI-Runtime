//! Sync capture buffer for session-supervisor exclusive stdout/stderr drain.
//!
//! Mirrors `executor::io` `OutputBuffer` semantics (byte sequences, EOF width 1,
//! eviction → stale-cursor fail-closed) without Tokio. The supervisor process is
//! a sync control loop; Host consumers read chunks only through control IPC.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use a3s_oci_sdk::{Error, ErrorCode, OutputChunk, OutputStream, Result};

/// Must match `io::OUTPUT_BUFFER_BYTES`.
pub(super) const OUTPUT_BUFFER_BYTES: usize = 8 * 1024 * 1024;
/// Must match `io::OUTPUT_READER_CHUNK_BYTES`.
pub(super) const OUTPUT_READER_CHUNK_BYTES: usize = 16 * 1024;

/// Bounded, ordered capture buffer drained by exclusive supervisor readers.
#[derive(Debug)]
pub(super) struct SyncOutputBuffer {
    state: Mutex<OutputState>,
    changed: Condvar,
}

#[derive(Debug)]
struct OutputState {
    chunks: VecDeque<BufferedChunk>,
    retained_bytes: usize,
    next_sequence: u64,
    dropped_through: u64,
    open_streams: u8,
    terminal_error: Option<String>,
}

#[derive(Debug)]
struct BufferedChunk {
    start_sequence: u64,
    end_sequence: u64,
    stream: OutputStream,
    data: Vec<u8>,
    eof: bool,
}

enum OutputPoll {
    Ready(Vec<OutputChunk>),
    Complete,
    Pending,
}

impl SyncOutputBuffer {
    pub(super) fn new(open_streams: u8) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(OutputState {
                chunks: VecDeque::new(),
                retained_bytes: 0,
                next_sequence: 1,
                dropped_through: 0,
                open_streams,
                terminal_error: None,
            }),
            changed: Condvar::new(),
        })
    }

    pub(super) fn append(self: &Arc<Self>, stream: OutputStream, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Err(error) = state.append(stream, data, false) {
            state.terminal_error.get_or_insert(error.message);
        }
        self.changed.notify_all();
    }

    pub(super) fn finish(self: &Arc<Self>, stream: OutputStream, error: Option<std::io::Error>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(error) = error {
            state
                .terminal_error
                .get_or_insert_with(|| format!("failed to drain captured {stream:?}: {error}"));
        }
        if state.open_streams > 0 {
            state.open_streams -= 1;
        }
        if let Err(error) = state.append(stream, Vec::new(), true) {
            state.terminal_error.get_or_insert(error.message);
        }
        self.changed.notify_all();
    }

    pub(super) fn read(
        &self,
        after_sequence: u64,
        max_bytes: u32,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Vec<OutputChunk>> {
        let deadline = wait_timeout_ms
            .filter(|timeout| *timeout > 0)
            .map(|timeout| Instant::now() + Duration::from_millis(timeout));
        let mut state = self.state.lock().map_err(|_| {
            buffer_error(
                ErrorCode::Internal,
                "session supervisor output buffer lock is poisoned",
            )
        })?;
        loop {
            match state.poll(after_sequence, max_bytes as usize)? {
                OutputPoll::Ready(chunks) => return Ok(chunks),
                OutputPoll::Complete => return Ok(Vec::new()),
                OutputPoll::Pending => {}
            }

            let Some(deadline) = deadline else {
                return Ok(Vec::new());
            };
            let now = Instant::now();
            if now >= deadline {
                return Ok(Vec::new());
            }
            let (guard, _) = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .map_err(|_| {
                    buffer_error(
                        ErrorCode::Internal,
                        "session supervisor output buffer wait failed",
                    )
                })?;
            state = guard;
        }
    }
}

impl OutputState {
    fn append(&mut self, stream: OutputStream, data: Vec<u8>, eof: bool) -> Result<()> {
        let width = if eof {
            1
        } else {
            u64::try_from(data.len()).map_err(|_| sequence_exhausted())?
        };
        let next = self
            .next_sequence
            .checked_add(width)
            .ok_or_else(sequence_exhausted)?;
        let start_sequence = self.next_sequence;
        let end_sequence = next - 1;
        self.next_sequence = next;
        self.retained_bytes = self.retained_bytes.checked_add(data.len()).ok_or_else(|| {
            buffer_error(
                ErrorCode::ResourceExhausted,
                "process output buffer byte accounting overflowed",
            )
        })?;
        self.chunks.push_back(BufferedChunk {
            start_sequence,
            end_sequence,
            stream,
            data,
            eof,
        });
        while self.retained_bytes > OUTPUT_BUFFER_BYTES {
            let Some(dropped) = self.chunks.pop_front() else {
                break;
            };
            self.retained_bytes = self
                .retained_bytes
                .checked_sub(dropped.data.len())
                .ok_or_else(|| {
                    buffer_error(
                        ErrorCode::Internal,
                        "process output buffer byte accounting became inconsistent",
                    )
                })?;
            self.dropped_through = dropped.end_sequence;
        }
        Ok(())
    }

    fn poll(&self, after_sequence: u64, max_bytes: usize) -> Result<OutputPoll> {
        if after_sequence < self.dropped_through {
            return Err(buffer_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "output cursor {after_sequence} fell behind retained cursor {}; \
                     restart from the retained cursor",
                    self.dropped_through
                ),
            ));
        }
        if after_sequence >= self.next_sequence {
            return Err(buffer_error(
                ErrorCode::InvalidArgument,
                format!(
                    "output cursor {after_sequence} is ahead of latest cursor {}",
                    self.next_sequence - 1
                ),
            ));
        }

        let mut remaining = max_bytes;
        let mut output = Vec::new();
        for chunk in &self.chunks {
            if chunk.end_sequence <= after_sequence {
                continue;
            }
            if chunk.eof {
                output.push(OutputChunk {
                    sequence: chunk.end_sequence,
                    stream: chunk.stream,
                    data: Vec::new(),
                    eof: true,
                });
                continue;
            }
            if remaining == 0 {
                break;
            }
            let offset = if after_sequence >= chunk.start_sequence {
                usize::try_from(after_sequence - chunk.start_sequence + 1)
                    .map_err(|_| sequence_exhausted())?
            } else {
                0
            };
            let available = chunk.data.len().saturating_sub(offset);
            let length = available.min(remaining);
            if length == 0 {
                continue;
            }
            let sequence = chunk
                .start_sequence
                .checked_add(u64::try_from(offset + length - 1).map_err(|_| sequence_exhausted())?)
                .ok_or_else(sequence_exhausted)?;
            output.push(OutputChunk {
                sequence,
                stream: chunk.stream,
                data: chunk.data[offset..offset + length].to_vec(),
                eof: false,
            });
            remaining -= length;
            if length < available {
                break;
            }
        }
        if !output.is_empty() {
            return Ok(OutputPoll::Ready(output));
        }
        if self.open_streams == 0 {
            if let Some(message) = &self.terminal_error {
                Err(buffer_error(ErrorCode::Internal, message.clone()))
            } else {
                Ok(OutputPoll::Complete)
            }
        } else {
            Ok(OutputPoll::Pending)
        }
    }
}

fn sequence_exhausted() -> Error {
    buffer_error(
        ErrorCode::ResourceExhausted,
        "process output sequence space is exhausted",
    )
}

fn buffer_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_read_and_eof_match_host_buffer_cursor_rules() {
        let buffer = SyncOutputBuffer::new(1);
        buffer.append(OutputStream::Stdout, b"abc".to_vec());
        let chunks = buffer.read(0, 8, None).expect("read deposited bytes");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].sequence, 3);
        assert_eq!(chunks[0].data, b"abc");
        assert!(!chunks[0].eof);

        buffer.finish(OutputStream::Stdout, None);
        let eof = buffer.read(3, 8, None).expect("read authentic EOF");
        assert_eq!(eof.len(), 1);
        assert!(eof[0].eof);
        assert!(eof[0].data.is_empty());
        assert_eq!(eof[0].sequence, 4);

        let done = buffer
            .read(4, 8, None)
            .expect("complete stream returns empty success");
        assert!(done.is_empty());
    }

    #[test]
    fn stale_cursor_fail_closes_without_inventing_bytes() {
        let buffer = SyncOutputBuffer::new(1);
        let oversized = vec![b'x'; OUTPUT_BUFFER_BYTES + 64];
        buffer.append(OutputStream::Stdout, oversized);
        let error = buffer
            .read(0, 16, None)
            .expect_err("evicted cursor must fail closed");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
    }
}
