use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_sdk::{Error, ErrorCode, IoMode, OutputChunk, OutputStream, ProcessIo, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant};

use super::terminal::{TerminalHandle, TerminalSetup};

const OUTPUT_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const OUTPUT_READER_CHUNK_BYTES: usize = 16 * 1024;

/// Live standard-I/O ownership for one init or exec process.
///
/// The child pipes are removed from `tokio::process::Child` immediately after
/// spawn. Dedicated readers continuously drain captured output into one
/// bounded, ordered buffer, while stdin writes retain Tokio backpressure.
#[derive(Debug, Clone)]
pub(super) struct ProcessIoHandle {
    inner: Arc<ProcessIoInner>,
}

#[derive(Debug)]
struct ProcessIoInner {
    stdin_mode: IoMode,
    stdin: Mutex<Option<ProcessStdin>>,
    next_stdin_operation: AtomicU64,
    serving_stdin_operation: watch::Sender<u64>,
    output: Option<Arc<OutputBuffer>>,
    terminal: Option<TerminalHandle>,
}

#[derive(Debug)]
enum ProcessStdin {
    Pipe(ChildStdin),
    Terminal(TerminalHandle),
}

/// One stdin mutation reserved in caller order before any backpressured I/O.
#[derive(Debug)]
struct ReservedStdinOperation {
    inner: Arc<ProcessIoInner>,
    sequence: u64,
}

/// Process descriptors prepared before `Command::spawn`.
#[derive(Debug)]
pub(super) struct ProcessIoSetup {
    terminal: Option<TerminalSetup>,
}

impl ProcessIoHandle {
    /// Configure supported child descriptors before spawn.
    pub(super) fn configure(command: &mut Command, io: &ProcessIo) -> Result<ProcessIoSetup> {
        if terminal_io(io) {
            let size = io.terminal_size.ok_or_else(|| {
                io_error(
                    ErrorCode::InvalidArgument,
                    "terminal process I/O requires an initial terminal size",
                )
            })?;
            return TerminalSetup::configure(command, size).map(|terminal| ProcessIoSetup {
                terminal: Some(terminal),
            });
        }
        if matches!(io.stdin, IoMode::Terminal)
            || matches!(io.stdout, IoMode::Terminal)
            || matches!(io.stderr, IoMode::Terminal)
            || io.terminal_size.is_some()
        {
            return Err(io_error(
                ErrorCode::InvalidArgument,
                "terminal process I/O requires terminal stdin, stdout, stderr, and size",
            ));
        }
        command.stdin(match io.stdin {
            IoMode::Null => std::process::Stdio::null(),
            IoMode::Pipe => std::process::Stdio::piped(),
            IoMode::Inherit => std::process::Stdio::inherit(),
            mode => return Err(unsupported_mode("stdin", mode)),
        });
        command.stdout(match io.stdout {
            IoMode::Null => std::process::Stdio::null(),
            IoMode::Capture => std::process::Stdio::piped(),
            IoMode::Inherit => std::process::Stdio::inherit(),
            mode => return Err(unsupported_mode("stdout", mode)),
        });
        command.stderr(match io.stderr {
            IoMode::Null => std::process::Stdio::null(),
            IoMode::Capture => std::process::Stdio::piped(),
            IoMode::Inherit => std::process::Stdio::inherit(),
            mode => return Err(unsupported_mode("stderr", mode)),
        });
        Ok(ProcessIoSetup { terminal: None })
    }

    /// Take configured descriptors from a newly spawned child and start
    /// non-blocking output drains.
    pub(super) fn attach(setup: ProcessIoSetup, child: &mut Child, io: &ProcessIo) -> Result<Self> {
        if let Some(terminal) = setup.terminal {
            let terminal = terminal.attach()?;
            let output = Arc::new(OutputBuffer::new(1));
            let (serving_stdin_operation, _) = watch::channel(0);
            spawn_terminal_reader(terminal.clone(), Arc::clone(&output));
            return Ok(Self {
                inner: Arc::new(ProcessIoInner {
                    stdin_mode: IoMode::Terminal,
                    stdin: Mutex::new(Some(ProcessStdin::Terminal(terminal.clone()))),
                    next_stdin_operation: AtomicU64::new(0),
                    serving_stdin_operation,
                    output: Some(output),
                    terminal: Some(terminal),
                }),
            });
        }
        let stdin = match io.stdin {
            IoMode::Pipe => Some(ProcessStdin::Pipe(child.stdin.take().ok_or_else(|| {
                io_error(
                    ErrorCode::Internal,
                    "spawned process did not expose its configured stdin pipe",
                )
            })?)),
            IoMode::Null | IoMode::Inherit => None,
            mode => return Err(unsupported_mode("stdin", mode)),
        };
        let stdout = match io.stdout {
            IoMode::Capture => Some(child.stdout.take().ok_or_else(|| {
                io_error(
                    ErrorCode::Internal,
                    "spawned process did not expose its configured stdout pipe",
                )
            })?),
            IoMode::Null | IoMode::Inherit => None,
            mode => return Err(unsupported_mode("stdout", mode)),
        };
        let stderr = match io.stderr {
            IoMode::Capture => Some(child.stderr.take().ok_or_else(|| {
                io_error(
                    ErrorCode::Internal,
                    "spawned process did not expose its configured stderr pipe",
                )
            })?),
            IoMode::Null | IoMode::Inherit => None,
            mode => return Err(unsupported_mode("stderr", mode)),
        };

        let captured_streams = usize::from(stdout.is_some()) + usize::from(stderr.is_some());
        let output =
            (captured_streams > 0).then(|| Arc::new(OutputBuffer::new(captured_streams as u8)));
        if let (Some(reader), Some(buffer)) = (stdout, output.as_ref()) {
            spawn_output_reader(reader, OutputStream::Stdout, Arc::clone(buffer));
        }
        if let (Some(reader), Some(buffer)) = (stderr, output.as_ref()) {
            spawn_output_reader(reader, OutputStream::Stderr, Arc::clone(buffer));
        }

        let (serving_stdin_operation, _) = watch::channel(0);
        Ok(Self {
            inner: Arc::new(ProcessIoInner {
                stdin_mode: io.stdin,
                stdin: Mutex::new(stdin),
                next_stdin_operation: AtomicU64::new(0),
                serving_stdin_operation,
                output,
                terminal: None,
            }),
        })
    }

    pub(super) async fn read_output(
        &self,
        after_sequence: u64,
        max_bytes: u32,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Vec<OutputChunk>> {
        let output = self.inner.output.as_ref().ok_or_else(|| {
            io_error(
                ErrorCode::FailedPrecondition,
                "process stdout and stderr were not configured for capture",
            )
        })?;
        output
            .read(after_sequence, max_bytes, wait_timeout_ms)
            .await
    }

    #[cfg(test)]
    async fn write_stdin(&self, data: &[u8]) -> Result<()> {
        self.spawn_write_stdin(data.to_vec())?
            .await
            .map_err(stdin_operation_task_error)?
    }

    /// Reserve and detach one ordered stdin write before returning its waiter.
    ///
    /// Dropping the caller's future therefore cannot abandon a reserved
    /// sequence and permanently block every later stdin mutation.
    pub(super) fn spawn_write_stdin(&self, data: Vec<u8>) -> Result<JoinHandle<Result<()>>> {
        let operation = self.reserve_stdin_operation()?;
        Ok(tokio::spawn(async move { operation.write(&data).await }))
    }

    fn reserve_stdin_operation(&self) -> Result<ReservedStdinOperation> {
        if !matches!(self.inner.stdin_mode, IoMode::Pipe | IoMode::Terminal) {
            return Err(io_error(
                ErrorCode::FailedPrecondition,
                "process stdin was not configured as a pipe or terminal",
            ));
        }
        let sequence = self
            .inner
            .next_stdin_operation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| {
                io_error(
                    ErrorCode::ResourceExhausted,
                    "process stdin operation sequence space is exhausted",
                )
            })?;
        Ok(ReservedStdinOperation {
            inner: Arc::clone(&self.inner),
            sequence,
        })
    }

    async fn write_stdin_reserved(&self, data: &[u8]) -> Result<()> {
        let mut stdin = self.inner.stdin.lock().await;
        let stdin = stdin.as_mut().ok_or_else(|| {
            io_error(
                ErrorCode::FailedPrecondition,
                "process stdin has already been closed",
            )
        })?;
        match stdin {
            ProcessStdin::Pipe(stdin) => {
                stdin.write_all(data).await.map_err(stdin_write_error)?;
                stdin.flush().await.map_err(stdin_write_error)
            }
            ProcessStdin::Terminal(terminal) => {
                terminal.write_all(data).await.map_err(stdin_write_error)
            }
        }
    }

    /// Reserve and detach an ordered stdin close before returning its waiter.
    pub(super) fn spawn_close_stdin(&self) -> Result<JoinHandle<Result<()>>> {
        let operation = self.reserve_stdin_operation()?;
        Ok(tokio::spawn(async move { operation.close().await }))
    }

    async fn close_stdin_reserved(&self) -> Result<()> {
        let mut stdin = self.inner.stdin.lock().await;
        if let Some(ProcessStdin::Terminal(terminal)) = stdin.as_ref() {
            terminal.close_input().await.map_err(stdin_write_error)?;
        }
        stdin.take();
        Ok(())
    }

    pub(super) fn resize(&self, size: a3s_oci_sdk::TerminalSize) -> Result<()> {
        self.inner
            .terminal
            .as_ref()
            .ok_or_else(|| {
                io_error(
                    ErrorCode::FailedPrecondition,
                    "process was not configured with a terminal",
                )
            })?
            .resize(size)
    }
}

impl ReservedStdinOperation {
    pub(super) async fn write(self, data: &[u8]) -> Result<()> {
        let io = ProcessIoHandle {
            inner: Arc::clone(&self.inner),
        };
        let _turn = self.wait_for_turn().await?;
        io.write_stdin_reserved(data).await
    }

    pub(super) async fn close(self) -> Result<()> {
        let io = ProcessIoHandle {
            inner: Arc::clone(&self.inner),
        };
        let _turn = self.wait_for_turn().await?;
        io.close_stdin_reserved().await
    }

    async fn wait_for_turn(&self) -> Result<StdinOperationTurn> {
        let mut serving = self.inner.serving_stdin_operation.subscribe();
        loop {
            let current = *serving.borrow_and_update();
            if current == self.sequence {
                return Ok(StdinOperationTurn {
                    inner: Arc::clone(&self.inner),
                    sequence: self.sequence,
                });
            }
            if current > self.sequence {
                return Err(io_error(
                    ErrorCode::Internal,
                    format!(
                        "process stdin operation {} was skipped at sequence {current}",
                        self.sequence
                    ),
                ));
            }
            serving.changed().await.map_err(|_| {
                io_error(
                    ErrorCode::Internal,
                    "process stdin operation sequencer closed unexpectedly",
                )
            })?;
        }
    }
}

struct StdinOperationTurn {
    inner: Arc<ProcessIoInner>,
    sequence: u64,
}

impl Drop for StdinOperationTurn {
    fn drop(&mut self) {
        if *self.inner.serving_stdin_operation.borrow() == self.sequence {
            self.inner
                .serving_stdin_operation
                .send_replace(self.sequence.saturating_add(1));
        }
    }
}

impl ProcessIoSetup {
    pub(super) const fn uses_terminal(&self) -> bool {
        self.terminal.is_some()
    }
}

#[derive(Debug)]
struct OutputBuffer {
    state: Mutex<OutputState>,
    changed: watch::Sender<u64>,
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

impl OutputBuffer {
    fn new(open_streams: u8) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            state: Mutex::new(OutputState {
                chunks: VecDeque::new(),
                retained_bytes: 0,
                next_sequence: 1,
                dropped_through: 0,
                open_streams,
                terminal_error: None,
            }),
            changed,
        }
    }

    async fn append(&self, stream: OutputStream, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let mut state = self.state.lock().await;
        if let Err(error) = state.append(stream, data, false) {
            state.terminal_error.get_or_insert(error.message);
        }
        self.changed.send_replace(state.next_sequence);
    }

    async fn finish(&self, stream: OutputStream, error: Option<std::io::Error>) {
        let mut state = self.state.lock().await;
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
        self.changed.send_replace(state.next_sequence);
    }

    async fn read(
        &self,
        after_sequence: u64,
        max_bytes: u32,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Vec<OutputChunk>> {
        let deadline = wait_timeout_ms
            .filter(|timeout| *timeout > 0)
            .map(|timeout| Instant::now() + Duration::from_millis(timeout));
        let mut changed = self.changed.subscribe();
        loop {
            match self
                .state
                .lock()
                .await
                .poll(after_sequence, max_bytes as usize)?
            {
                OutputPoll::Ready(chunks) => return Ok(chunks),
                OutputPoll::Complete => return Ok(Vec::new()),
                OutputPoll::Pending => {}
            }

            let Some(deadline) = deadline else {
                return Ok(Vec::new());
            };
            if timeout_at(deadline, changed.changed()).await.is_err() {
                return Ok(Vec::new());
            }
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
            io_error(
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
                    io_error(
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
            return Err(io_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "output cursor {after_sequence} fell behind retained cursor {}; \
                     restart from the retained cursor",
                    self.dropped_through
                ),
            ));
        }
        if after_sequence >= self.next_sequence {
            return Err(io_error(
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
                Err(io_error(ErrorCode::Internal, message.clone()))
            } else {
                Ok(OutputPoll::Complete)
            }
        } else {
            Ok(OutputPoll::Pending)
        }
    }
}

fn spawn_output_reader(
    mut reader: impl AsyncRead + Unpin + Send + 'static,
    stream: OutputStream,
    buffer: Arc<OutputBuffer>,
) {
    tokio::spawn(async move {
        let mut bytes = vec![0_u8; OUTPUT_READER_CHUNK_BYTES];
        loop {
            match reader.read(&mut bytes).await {
                Ok(0) => {
                    buffer.finish(stream, None).await;
                    return;
                }
                Ok(length) => buffer.append(stream, bytes[..length].to_vec()).await,
                Err(error) => {
                    buffer.finish(stream, Some(error)).await;
                    return;
                }
            }
        }
    });
}

fn spawn_terminal_reader(terminal: TerminalHandle, buffer: Arc<OutputBuffer>) {
    tokio::spawn(async move {
        let mut bytes = vec![0_u8; OUTPUT_READER_CHUNK_BYTES];
        loop {
            match terminal.read(&mut bytes).await {
                Ok(0) => {
                    buffer.finish(OutputStream::Stdout, None).await;
                    return;
                }
                Ok(length) => {
                    buffer
                        .append(OutputStream::Stdout, bytes[..length].to_vec())
                        .await;
                }
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    // Linux returns EIO from a PTY master after its final slave
                    // closes; this is the terminal equivalent of pipe EOF.
                    buffer.finish(OutputStream::Stdout, None).await;
                    return;
                }
                Err(error) => {
                    buffer.finish(OutputStream::Stdout, Some(error)).await;
                    return;
                }
            }
        }
    });
}

fn terminal_io(io: &ProcessIo) -> bool {
    io.stdin == IoMode::Terminal && io.stdout == IoMode::Terminal && io.stderr == IoMode::Terminal
}

fn unsupported_mode(stream: &str, mode: IoMode) -> Error {
    io_error(
        ErrorCode::Unsupported,
        format!("process {stream} mode {mode:?} is not implemented by the Linux executor"),
    )
}

fn stdin_write_error(error: std::io::Error) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
            ErrorCode::FailedPrecondition
        }
        _ => ErrorCode::Internal,
    };
    io_error(code, format!("failed to write process stdin: {error}"))
}

#[cfg(test)]
fn stdin_operation_task_error(error: tokio::task::JoinError) -> Error {
    io_error(
        ErrorCode::Internal,
        format!("process stdin operation task failed: {error}"),
    )
}

fn sequence_exhausted() -> Error {
    io_error(
        ErrorCode::ResourceExhausted,
        "process output sequence space is exhausted",
    )
}

fn io_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("process-io")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use a3s_oci_sdk::{ErrorCode, IoMode, OutputStream, ProcessIo};
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};

    use super::{OutputBuffer, ProcessIoHandle, OUTPUT_BUFFER_BYTES};

    #[cfg(unix)]
    #[tokio::test]
    async fn inherited_descriptors_need_no_runtime_owned_pipe() {
        let io = ProcessIo {
            stdin: IoMode::Inherit,
            stdout: IoMode::Inherit,
            stderr: IoMode::Inherit,
            terminal_size: None,
        };
        let mut command = tokio::process::Command::new("true");
        let setup = ProcessIoHandle::configure(&mut command, &io)
            .expect("configure inherited process descriptors");
        let mut child = command.spawn().expect("spawn inherited-I/O process");
        let handle = ProcessIoHandle::attach(setup, &mut child, &io)
            .expect("attach inherited process descriptors");

        assert!(child.wait().await.expect("wait for process").success());
        assert_eq!(
            handle
                .read_output(0, 1, None)
                .await
                .expect_err("inherited output is not SDK-captured")
                .code,
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            handle
                .write_stdin(b"x")
                .await
                .expect_err("inherited stdin is not SDK-writable")
                .code,
            ErrorCode::FailedPrecondition
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reserved_stdin_mutations_keep_claim_order_under_backpressure() {
        let io = ProcessIo {
            stdin: IoMode::Pipe,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        };
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", "sleep 0.15; cat"]);
        command.stdout(std::process::Stdio::piped());
        let setup = ProcessIoHandle::configure(&mut command, &io)
            .expect("configure piped process descriptors");
        command.stdout(std::process::Stdio::piped());
        let mut child = command.spawn().expect("spawn delayed stdin reader");
        let mut stdout = child.stdout.take().expect("test stdout pipe");
        let handle = ProcessIoHandle::attach(setup, &mut child, &io)
            .expect("attach piped process descriptors");

        let first_data = vec![b'a'; 256 * 1024];
        let first_length = first_data.len();
        let first_task = handle
            .spawn_write_stdin(first_data)
            .expect("spawn first stdin operation");
        let second_task = handle
            .spawn_write_stdin(b"tail".to_vec())
            .expect("spawn second stdin operation");
        let close_task = handle.spawn_close_stdin().expect("spawn stdin close");

        timeout(Duration::from_secs(5), first_task)
            .await
            .expect("first write timeout")
            .expect("first write task")
            .expect("first write");
        timeout(Duration::from_secs(5), second_task)
            .await
            .expect("second write timeout")
            .expect("second write task")
            .expect("second write");
        timeout(Duration::from_secs(5), close_task)
            .await
            .expect("close timeout")
            .expect("close task")
            .expect("close stdin");

        let mut output = Vec::new();
        timeout(Duration::from_secs(5), stdout.read_to_end(&mut output))
            .await
            .expect("stdout read timeout")
            .expect("read stdout");
        assert_eq!(output.len(), first_length + 4);
        assert!(output[..first_length].iter().all(|byte| *byte == b'a'));
        assert_eq!(&output[first_length..], b"tail");
        assert!(child.wait().await.expect("wait delayed reader").success());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_stdin_caller_cannot_leave_a_sequence_hole() {
        let io = ProcessIo {
            stdin: IoMode::Pipe,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        };
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", "sleep 0.15; cat"]);
        command.stdout(std::process::Stdio::piped());
        let setup = ProcessIoHandle::configure(&mut command, &io)
            .expect("configure piped process descriptors");
        command.stdout(std::process::Stdio::piped());
        let mut child = command.spawn().expect("spawn delayed stdin reader");
        let mut stdout = child.stdout.take().expect("test stdout pipe");
        let handle = ProcessIoHandle::attach(setup, &mut child, &io)
            .expect("attach piped process descriptors");

        let first_length = 256 * 1024;
        let cancelled_handle = handle.clone();
        let cancelled = tokio::spawn(async move {
            cancelled_handle
                .write_stdin(&vec![b'a'; first_length])
                .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancelled.abort();
        assert!(
            cancelled
                .await
                .expect_err("caller must be cancelled")
                .is_cancelled(),
            "the detached stdin mutation must outlive only its cancelled caller"
        );

        let tail = handle
            .spawn_write_stdin(b"tail".to_vec())
            .expect("spawn trailing stdin operation");
        let close = handle
            .spawn_close_stdin()
            .expect("spawn trailing stdin close");
        timeout(Duration::from_secs(5), tail)
            .await
            .expect("tail write timeout")
            .expect("tail write task")
            .expect("tail write");
        timeout(Duration::from_secs(5), close)
            .await
            .expect("close timeout")
            .expect("close task")
            .expect("close stdin");

        let mut output = Vec::new();
        timeout(Duration::from_secs(5), stdout.read_to_end(&mut output))
            .await
            .expect("stdout read timeout")
            .expect("read stdout");
        assert_eq!(output.len(), first_length + 4);
        assert!(output[..first_length].iter().all(|byte| *byte == b'a'));
        assert_eq!(&output[first_length..], b"tail");
        assert!(child.wait().await.expect("wait delayed reader").success());
    }

    #[tokio::test]
    async fn output_cursor_splits_frames_without_exceeding_byte_limit() {
        let buffer = OutputBuffer::new(1);
        buffer
            .append(OutputStream::Stdout, b"abcdef".to_vec())
            .await;
        buffer.finish(OutputStream::Stdout, None).await;

        let first = buffer.read(0, 2, None).await.expect("first output poll");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].sequence, 2);
        assert_eq!(first[0].data, b"ab");

        let second = buffer
            .read(first[0].sequence, 3, None)
            .await
            .expect("second output poll");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].sequence, 5);
        assert_eq!(second[0].data, b"cde");

        let final_poll = buffer
            .read(second[0].sequence, 2, None)
            .await
            .expect("final output poll");
        assert_eq!(final_poll.len(), 2);
        assert_eq!(final_poll[0].data, b"f");
        assert!(final_poll[1].eof);
        assert!(buffer
            .read(final_poll[1].sequence, 1, None)
            .await
            .expect("completed poll")
            .is_empty());
    }

    #[tokio::test]
    async fn stale_and_future_cursors_fail_closed() {
        let buffer = OutputBuffer::new(1);
        buffer
            .append(OutputStream::Stdout, vec![b'x'; OUTPUT_BUFFER_BYTES + 1])
            .await;

        let stale = buffer
            .read(0, 1, None)
            .await
            .expect_err("evicted cursor must fail");
        assert_eq!(stale.code, ErrorCode::ResourceExhausted);

        let future = buffer
            .read(u64::MAX, 1, None)
            .await
            .expect_err("future cursor must fail");
        assert_eq!(future.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn long_poll_wakes_for_new_output() {
        let buffer = Arc::new(OutputBuffer::new(1));
        let waiting = {
            let buffer = Arc::clone(&buffer);
            tokio::spawn(async move { buffer.read(0, 8, Some(1_000)).await })
        };
        buffer.append(OutputStream::Stderr, b"ready".to_vec()).await;

        let chunks = waiting.await.expect("poll task").expect("long-poll result");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].stream, OutputStream::Stderr);
        assert_eq!(chunks[0].data, b"ready");
    }

    #[tokio::test]
    async fn drain_error_does_not_hide_another_open_stream() {
        let buffer = OutputBuffer::new(2);
        buffer
            .finish(
                OutputStream::Stdout,
                Some(std::io::Error::other("stdout failed")),
            )
            .await;

        let stdout_eof = buffer.read(0, 8, None).await.expect("stdout EOF");
        assert_eq!(stdout_eof.len(), 1);
        assert!(stdout_eof[0].eof);
        assert!(buffer
            .read(stdout_eof[0].sequence, 8, None)
            .await
            .expect("stderr remains open")
            .is_empty());

        buffer
            .append(OutputStream::Stderr, b"still readable".to_vec())
            .await;
        let stderr = buffer
            .read(stdout_eof[0].sequence, 32, None)
            .await
            .expect("stderr output");
        assert_eq!(stderr.len(), 1);
        assert_eq!(stderr[0].data, b"still readable");

        buffer.finish(OutputStream::Stderr, None).await;
        let stderr_eof = buffer
            .read(stderr[0].sequence, 8, None)
            .await
            .expect("stderr EOF");
        assert_eq!(stderr_eof.len(), 1);
        assert!(stderr_eof[0].eof);
        let error = buffer
            .read(stderr_eof[0].sequence, 8, None)
            .await
            .expect_err("drain error after all streams close");
        assert_eq!(error.code, ErrorCode::Internal);
    }
}
