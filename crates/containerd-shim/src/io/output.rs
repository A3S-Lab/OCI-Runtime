use super::*;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputWriteOutcome {
    Complete,
    Stopped,
}

pub(super) struct OutputPumpEndpoints {
    pub(super) stdout: Option<AsyncFd<File>>,
    pub(super) stderr: Option<AsyncFd<File>>,
    pub(super) terminal: bool,
    pub(super) cursor: u64,
    pub(super) cursor_committer: Option<Arc<dyn OutputCursorCommitter>>,
}

pub(super) async fn pump_output(
    adapter: RuntimeAdapter,
    target: a3s_oci_sdk::ProcessTarget,
    endpoints: OutputPumpEndpoints,
    mut cancelled: watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    let mut cursor = endpoints.cursor;
    let mut stdout_done = !endpoints.terminal && endpoints.stdout.is_none();
    let mut stderr_done = endpoints.terminal || endpoints.stderr.is_none();
    while !(stdout_done && stderr_done) {
        let Some(chunks) = cancellable_request(
            &mut cancelled,
            "read runtime output for containerd",
            adapter.read_output(
                target.clone(),
                cursor,
                OUTPUT_READ_BYTES,
                Some(OUTPUT_WAIT_MILLIS),
            ),
        )
        .await?
        else {
            return Ok(());
        };
        for chunk in chunks {
            let next_cursor = validate_output_chunk(&chunk, cursor)?;
            validate_output_stream_state(&chunk, endpoints.terminal, stdout_done, stderr_done)?;
            let mut committed_incrementally = false;
            match chunk.stream {
                OutputStream::Stdout => {
                    if !chunk.data.is_empty() {
                        if let Some(fifo) = &endpoints.stdout {
                            if write_output_chunk(
                                fifo,
                                &chunk.data,
                                &mut cursor,
                                endpoints.cursor_committer.as_deref(),
                                &mut cancelled,
                            )
                            .await?
                                == OutputWriteOutcome::Stopped
                            {
                                return Ok(());
                            }
                            committed_incrementally = true;
                        } else if !endpoints.terminal {
                            return Err(RuntimeError::new(
                                ErrorCode::Internal,
                                "runtime returned stdout for a process configured without stdout capture",
                            )
                            .for_operation("containerd-stdio"));
                        }
                    }
                    stdout_done |= chunk.eof;
                }
                OutputStream::Stderr => {
                    if !chunk.data.is_empty() {
                        if let Some(fifo) = &endpoints.stderr {
                            if write_output_chunk(
                                fifo,
                                &chunk.data,
                                &mut cursor,
                                endpoints.cursor_committer.as_deref(),
                                &mut cancelled,
                            )
                            .await?
                                == OutputWriteOutcome::Stopped
                            {
                                return Ok(());
                            }
                            committed_incrementally = true;
                        } else {
                            return Err(RuntimeError::new(
                                ErrorCode::Internal,
                                "runtime returned stderr for a process configured without stderr capture",
                            )
                            .for_operation("containerd-stdio"));
                        }
                    }
                    stderr_done |= chunk.eof;
                }
            }
            if committed_incrementally {
                debug_assert_eq!(cursor, next_cursor);
            } else {
                if let Some(committer) = &endpoints.cursor_committer {
                    committer.commit(next_cursor).await?;
                }
                cursor = next_cursor;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_output_chunk(
    chunk: &a3s_oci_sdk::OutputChunk,
    cursor: u64,
) -> Result<u64, RuntimeError> {
    let width = match (chunk.eof, chunk.data.is_empty()) {
        (false, false) => u64::try_from(chunk.data.len()).map_err(|_| {
            RuntimeError::new(
                ErrorCode::ResourceExhausted,
                "runtime output chunk length does not fit its byte cursor",
            )
            .for_operation("containerd-stdio")
        })?,
        (true, true) => 1,
        (false, true) => {
            return Err(RuntimeError::new(
                ErrorCode::Internal,
                "runtime returned an empty output data chunk",
            )
            .for_operation("containerd-stdio"));
        }
        (true, false) => {
            return Err(RuntimeError::new(
                ErrorCode::Internal,
                "runtime returned output data in an EOF chunk",
            )
            .for_operation("containerd-stdio"));
        }
    };
    let expected = cursor.checked_add(width).ok_or_else(|| {
        RuntimeError::new(
            ErrorCode::ResourceExhausted,
            "containerd output cursor space is exhausted",
        )
        .for_operation("containerd-stdio")
    })?;
    if chunk.sequence != expected {
        return Err(RuntimeError::new(
            ErrorCode::Internal,
            format!(
                "runtime output cursor is not contiguous: received {}, expected {expected}",
                chunk.sequence
            ),
        )
        .for_operation("containerd-stdio"));
    }
    Ok(expected)
}

pub(super) fn validate_output_stream_state(
    chunk: &a3s_oci_sdk::OutputChunk,
    terminal: bool,
    stdout_done: bool,
    stderr_done: bool,
) -> Result<(), RuntimeError> {
    let message = match chunk.stream {
        OutputStream::Stdout if stdout_done => Some("runtime returned stdout after its EOF cursor"),
        OutputStream::Stderr if terminal => {
            Some("runtime returned a separate stderr stream for terminal I/O")
        }
        OutputStream::Stderr if stderr_done => Some("runtime returned stderr after its EOF cursor"),
        OutputStream::Stdout | OutputStream::Stderr => None,
    };
    if let Some(message) = message {
        return Err(
            RuntimeError::new(ErrorCode::Internal, message).for_operation("containerd-stdio")
        );
    }
    Ok(())
}

async fn write_output_chunk(
    fifo: &AsyncFd<File>,
    mut bytes: &[u8],
    cursor: &mut u64,
    cursor_committer: Option<&dyn OutputCursorCommitter>,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<OutputWriteOutcome, RuntimeError> {
    while !bytes.is_empty() {
        let written = tokio::select! {
            changed = cancelled.changed() => {
                if changed.is_err() || *cancelled.borrow() {
                    return Ok(OutputWriteOutcome::Stopped);
                }
                continue;
            }
            result = fifo.async_io(Interest::WRITABLE, |file| (&*file).write(bytes)) => {
                result.map_err(|error| io_error("write containerd output FIFO", error))?
            }
        };
        if written == 0 {
            return Err(io_error(
                "write containerd output FIFO",
                io::Error::new(io::ErrorKind::WriteZero, "FIFO accepted zero bytes"),
            ));
        }
        let next_cursor = cursor
            .checked_add(u64::try_from(written).map_err(|_| {
                RuntimeError::new(
                    ErrorCode::ResourceExhausted,
                    "containerd output write length does not fit its byte cursor",
                )
                .for_operation("containerd-stdio")
            })?)
            .ok_or_else(|| {
                RuntimeError::new(
                    ErrorCode::ResourceExhausted,
                    "containerd output cursor space is exhausted",
                )
                .for_operation("containerd-stdio")
            })?;
        if let Some(committer) = cursor_committer {
            committer.commit(next_cursor).await?;
        }
        *cursor = next_cursor;
        bytes = &bytes[written..];
    }
    Ok(OutputWriteOutcome::Complete)
}
