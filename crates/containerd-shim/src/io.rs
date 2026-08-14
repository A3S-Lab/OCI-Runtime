use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_sdk::{Error as RuntimeError, ErrorCode, Generation, OutputStream};
use async_trait::async_trait;
use tokio::io::{unix::AsyncFd, Interest};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::adapter::{RuntimeAdapter, TaskIdentity};

const FIFO_BUFFER_BYTES: usize = 64 * 1024;
const OUTPUT_READ_BYTES: u32 = 64 * 1024;
const OUTPUT_WAIT_MILLIS: u64 = 250;
const PUMP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PUMP_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const STDIN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct PumpCancellation {
    sender: watch::Sender<bool>,
}

impl PumpCancellation {
    pub(crate) fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    pub(crate) fn cancel(&self) {
        self.sender.send_replace(true);
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }
}

pub(crate) struct ProcessPumps {
    cancellation: PumpCancellation,
    tasks: Vec<JoinHandle<Result<(), RuntimeError>>>,
    failures: mpsc::UnboundedReceiver<RuntimeError>,
    stdin_drain: Option<StdinDrain>,
}

#[derive(Clone)]
pub(crate) struct StdinDrain {
    request: watch::Sender<bool>,
    activation: Option<watch::Sender<bool>>,
    completion: watch::Receiver<Option<Result<(), RuntimeError>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinPumpOutcome {
    Drained,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinTargetState {
    Exited,
    LiveOrUnknown,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinStartup {
    Activated,
    DrainRequested,
    Stopped,
}

pub(crate) struct ProcessIoEndpoints<'a> {
    pub(crate) stdin: &'a str,
    pub(crate) stdout: &'a str,
    pub(crate) stderr: &'a str,
    pub(crate) terminal: bool,
    pub(crate) await_start_activation: bool,
    pub(crate) output_cursor: u64,
    pub(crate) output_cursor_committer: Option<Arc<dyn OutputCursorCommitter>>,
}

struct OutputPumpEndpoints {
    stdout: Option<AsyncFd<File>>,
    stderr: Option<AsyncFd<File>>,
    terminal: bool,
    cursor: u64,
    cursor_committer: Option<Arc<dyn OutputCursorCommitter>>,
}

#[async_trait]
pub(crate) trait OutputCursorCommitter: Send + Sync {
    async fn commit(&self, cursor: u64) -> Result<(), RuntimeError>;
}

impl ProcessPumps {
    pub(crate) fn failure(&mut self) -> Option<RuntimeError> {
        self.failures.try_recv().ok()
    }

    pub(crate) fn stdin_drain(&self) -> Option<StdinDrain> {
        self.stdin_drain.clone()
    }

    pub(crate) fn activate_stdin(&self) {
        if let Some(drain) = &self.stdin_drain {
            drain.activate();
        }
    }

    pub(crate) async fn stop(mut self) {
        self.cancellation.cancel();
        for mut task in std::mem::take(&mut self.tasks) {
            match tokio::time::timeout(PUMP_STOP_TIMEOUT, &mut task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    log::warn!("containerd process I/O pump stopped with an error: {error}");
                }
                Ok(Err(error)) => {
                    log::warn!("containerd process I/O pump task failed: {error}");
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    log::warn!("containerd process I/O pump exceeded its shutdown deadline");
                }
            }
        }
    }
}

impl StdinDrain {
    fn activate(&self) {
        if let Some(activation) = &self.activation {
            activation.send_replace(true);
        }
    }

    pub(crate) async fn request_and_wait(mut self) -> Result<(), RuntimeError> {
        // containerd invokes CloseIO synchronously from the stdin reader when
        // that reader observes EOF. At that point all preceding FIFO writes
        // have completed, but containerd cannot close its FIFO writer until
        // CloseIO returns. The request tells the pump that no future bytes can
        // arrive, so the first nonblocking empty read is the true drain point.
        self.request.send_replace(true);
        self.wait_for_completion().await
    }

    async fn wait_for_completion(&mut self) -> Result<(), RuntimeError> {
        let completion = async {
            loop {
                if let Some(result) = self.completion.borrow().clone() {
                    return result;
                }
                self.completion.changed().await.map_err(|_| {
                    RuntimeError::new(
                        ErrorCode::Unavailable,
                        "containerd stdin pump stopped before reporting FIFO drain completion",
                    )
                    .for_operation("containerd-close-io")
                    .retryable(true)
                })?;
            }
        };
        tokio::time::timeout(STDIN_DRAIN_TIMEOUT, completion)
            .await
            .map_err(|_| {
                RuntimeError::new(
                    ErrorCode::DeadlineExceeded,
                    format!(
                        "containerd stdin FIFO did not drain within {} seconds",
                        STDIN_DRAIN_TIMEOUT.as_secs()
                    ),
                )
                .for_operation("containerd-close-io")
                .retryable(true)
            })?
    }
}

impl Drop for ProcessPumps {
    fn drop(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub(crate) fn start_process_pumps(
    adapter: RuntimeAdapter,
    task: TaskIdentity,
    generation: Generation,
    exec_id: Option<String>,
    endpoints: ProcessIoEndpoints<'_>,
) -> Result<ProcessPumps, RuntimeError> {
    validate_process_io_endpoints(&endpoints)?;
    let target = adapter.process_target(&task, generation, exec_id.as_deref())?;
    let cancellation = PumpCancellation::new();
    let (failure_sender, failures) = mpsc::unbounded_channel();
    let mut tasks = Vec::new();
    let mut stdin_drain = None;
    if !endpoints.stdin.is_empty() {
        let fifo = open_fifo(endpoints.stdin, true, false)?;
        let (drain_request, drain_requested) = watch::channel(false);
        let (activation_request, activation_requested) = if endpoints.await_start_activation {
            let (request, requested) = watch::channel(false);
            (Some(request), Some(requested))
        } else {
            (None, None)
        };
        let (task_handle, drain) = spawn_stdin_pump(
            failure_sender.clone(),
            drain_request,
            activation_request,
            pump_stdin(
                adapter.clone(),
                task,
                generation,
                exec_id,
                target.clone(),
                fifo,
                cancellation.subscribe(),
                drain_requested,
                activation_requested,
            ),
        );
        tasks.push(task_handle);
        stdin_drain = Some(drain);
    }
    if !endpoints.stdout.is_empty() || (!endpoints.terminal && !endpoints.stderr.is_empty()) {
        let stdout_fifo = (!endpoints.stdout.is_empty())
            .then(|| open_output_fifo(endpoints.stdout))
            .transpose()?;
        let stderr_fifo = (!endpoints.terminal && !endpoints.stderr.is_empty())
            .then(|| open_output_fifo(endpoints.stderr))
            .transpose()?;
        tasks.push(spawn_pump(
            "output",
            failure_sender,
            pump_output(
                adapter,
                target,
                OutputPumpEndpoints {
                    stdout: stdout_fifo,
                    stderr: stderr_fifo,
                    terminal: endpoints.terminal,
                    cursor: endpoints.output_cursor,
                    cursor_committer: endpoints.output_cursor_committer,
                },
                cancellation.subscribe(),
            ),
        ));
    }
    Ok(ProcessPumps {
        cancellation,
        tasks,
        failures,
        stdin_drain,
    })
}

fn validate_process_io_endpoints(endpoints: &ProcessIoEndpoints<'_>) -> Result<(), RuntimeError> {
    if endpoints.terminal && !endpoints.stderr.is_empty() {
        return Err(RuntimeError::new(
            ErrorCode::InvalidArgument,
            "containerd terminal I/O must use one merged stdout stream and omit stderr",
        )
        .for_operation("containerd-stdio"));
    }
    Ok(())
}

fn spawn_pump(
    name: &'static str,
    failure_sender: mpsc::UnboundedSender<RuntimeError>,
    pump: impl std::future::Future<Output = Result<(), RuntimeError>> + Send + 'static,
) -> JoinHandle<Result<(), RuntimeError>> {
    tokio::spawn(async move {
        let result = pump.await;
        if let Err(error) = &result {
            log::error!("containerd {name} pump failed: {error}");
            let _ = failure_sender.send(error.clone());
        }
        result
    })
}

fn spawn_stdin_pump(
    failure_sender: mpsc::UnboundedSender<RuntimeError>,
    request: watch::Sender<bool>,
    activation: Option<watch::Sender<bool>>,
    pump: impl std::future::Future<Output = Result<StdinPumpOutcome, RuntimeError>> + Send + 'static,
) -> (JoinHandle<Result<(), RuntimeError>>, StdinDrain) {
    let (completion_sender, completion) = watch::channel(None);
    let task = tokio::spawn(async move {
        let result = pump.await;
        let completion = match &result {
            Ok(StdinPumpOutcome::Drained) => Ok(()),
            Ok(StdinPumpOutcome::Stopped) => Err(RuntimeError::new(
                ErrorCode::Unavailable,
                "containerd stdin pump stopped before its FIFO was drained",
            )
            .for_operation("containerd-close-io")
            .retryable(true)),
            Err(error) => Err(error.clone()),
        };
        completion_sender.send_replace(Some(completion));
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                log::error!("containerd stdin pump failed: {error}");
                let _ = failure_sender.send(error.clone());
                Err(error)
            }
        }
    });
    (
        task,
        StdinDrain {
            request,
            activation,
            completion,
        },
    )
}

#[allow(clippy::too_many_arguments)]
async fn pump_stdin(
    adapter: RuntimeAdapter,
    task: TaskIdentity,
    generation: Generation,
    exec_id: Option<String>,
    target: a3s_oci_sdk::ProcessTarget,
    fifo: AsyncFd<File>,
    mut cancelled: watch::Receiver<bool>,
    mut drain_requested: watch::Receiver<bool>,
    mut activation_requested: Option<watch::Receiver<bool>>,
) -> Result<StdinPumpOutcome, RuntimeError> {
    let mut sequence = 0_u64;
    let mut buffer = vec![0_u8; FIFO_BUFFER_BYTES];
    if let Some(activation) = &mut activation_requested {
        match wait_for_stdin_activation(activation, &mut cancelled, &mut drain_requested).await? {
            StdinStartup::Activated => match read_fifo_nonblocking(fifo.get_ref(), &mut buffer)? {
                FifoRead::Bytes(length) => {
                    write_stdin_chunk(
                        &adapter,
                        &task,
                        generation,
                        exec_id.as_deref(),
                        &target,
                        &mut sequence,
                        &buffer[..length],
                        &mut cancelled,
                    )
                    .await?;
                }
                // EAGAIN proves that containerd's producer is connected but
                // has not emitted a byte yet. Continue waiting without
                // inventing EOF for delayed or interactive input.
                FifoRead::Empty => {}
                // containerd installs the fresh task's FIFO producer before
                // Start. EOF at the successful Start boundary therefore means
                // that an empty producer has already finished, possibly before
                // it could issue CloseIO.
                FifoRead::Eof => {
                    return close_runtime_stdin(
                        &adapter,
                        &task,
                        generation,
                        exec_id.as_deref(),
                        &target,
                        &mut cancelled,
                    )
                    .await;
                }
            },
            StdinStartup::DrainRequested => {}
            StdinStartup::Stopped => return Ok(StdinPumpOutcome::Stopped),
        }
    }
    loop {
        if *drain_requested.borrow() {
            match read_fifo_nonblocking(fifo.get_ref(), &mut buffer)? {
                FifoRead::Bytes(length) => {
                    write_stdin_chunk(
                        &adapter,
                        &task,
                        generation,
                        exec_id.as_deref(),
                        &target,
                        &mut sequence,
                        &buffer[..length],
                        &mut cancelled,
                    )
                    .await?;
                    continue;
                }
                FifoRead::Empty | FifoRead::Eof => {
                    return close_runtime_stdin(
                        &adapter,
                        &task,
                        generation,
                        exec_id.as_deref(),
                        &target,
                        &mut cancelled,
                    )
                    .await;
                }
            }
        }
        let length = tokio::select! {
            changed = cancelled.changed() => {
                if changed.is_err() || *cancelled.borrow() {
                    return Ok(StdinPumpOutcome::Stopped);
                }
                continue;
            }
            changed = drain_requested.changed() => {
                if changed.is_err() {
                    return Err(RuntimeError::new(
                        ErrorCode::Unavailable,
                        "containerd CloseIO request channel closed before stdin drain",
                    )
                    .for_operation("containerd-stdin")
                    .retryable(true));
                }
                continue;
            }
            result = fifo.async_io(Interest::READABLE, |file| (&*file).read(&mut buffer)) => {
                result.map_err(|error| io_error("read containerd stdin FIFO", error))?
            }
        };
        if length == 0 {
            return close_runtime_stdin(
                &adapter,
                &task,
                generation,
                exec_id.as_deref(),
                &target,
                &mut cancelled,
            )
            .await;
        }
        write_stdin_chunk(
            &adapter,
            &task,
            generation,
            exec_id.as_deref(),
            &target,
            &mut sequence,
            &buffer[..length],
            &mut cancelled,
        )
        .await?;
    }
}

async fn wait_for_stdin_activation(
    activation: &mut watch::Receiver<bool>,
    cancelled: &mut watch::Receiver<bool>,
    drain_requested: &mut watch::Receiver<bool>,
) -> Result<StdinStartup, RuntimeError> {
    loop {
        if *drain_requested.borrow() {
            return Ok(StdinStartup::DrainRequested);
        }
        if *activation.borrow() {
            return Ok(StdinStartup::Activated);
        }
        tokio::select! {
            changed = cancelled.changed() => {
                if changed.is_err() || *cancelled.borrow() {
                    return Ok(StdinStartup::Stopped);
                }
            }
            changed = drain_requested.changed() => {
                if changed.is_err() {
                    return Err(RuntimeError::new(
                        ErrorCode::Unavailable,
                        "containerd CloseIO request channel closed during stdin handshake",
                )
                    .for_operation("containerd-stdin")
                    .retryable(true));
                }
            }
            changed = activation.changed() => {
                if changed.is_err() {
                    return Err(RuntimeError::new(
                        ErrorCode::Unavailable,
                        "containerd stdin Start activation channel closed before activation",
                    )
                    .for_operation("containerd-stdin")
                    .retryable(true));
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FifoRead {
    Bytes(usize),
    Empty,
    Eof,
}

fn read_fifo_nonblocking(file: &File, buffer: &mut [u8]) -> Result<FifoRead, RuntimeError> {
    loop {
        match (&*file).read(buffer) {
            Ok(0) => return Ok(FifoRead::Eof),
            Ok(length) => return Ok(FifoRead::Bytes(length)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(FifoRead::Empty),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error("drain containerd stdin FIFO", error)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_stdin_chunk(
    adapter: &RuntimeAdapter,
    task: &TaskIdentity,
    generation: Generation,
    exec_id: Option<&str>,
    target: &a3s_oci_sdk::ProcessTarget,
    sequence: &mut u64,
    data: &[u8],
    cancelled: &mut watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            ErrorCode::ResourceExhausted,
            "containerd stdin pump sequence space is exhausted",
        )
        .for_operation("containerd-stdin")
    })?;
    let context = adapter.stdin_operation(task, exec_id, *sequence)?;
    let write = cancellable_request(
        cancelled,
        "write containerd stdin through the runtime SDK",
        adapter.write_stdin(target.clone(), context, data.to_vec()),
    )
    .await;
    match write {
        Ok(Some(())) => Ok(()),
        Ok(None) => Err(RuntimeError::new(
            ErrorCode::Unavailable,
            "containerd stdin pump stopped during an ordered write",
        )
        .for_operation("containerd-stdin")
        .retryable(true)),
        Err(error) => {
            match stdin_target_state(adapter, task, generation, target, &error, cancelled).await {
                StdinTargetState::Exited => Ok(()),
                StdinTargetState::Stopped => Err(RuntimeError::new(
                    ErrorCode::Unavailable,
                    "containerd stdin pump stopped while confirming a late write",
                )
                .for_operation("containerd-stdin")
                .retryable(true)),
                StdinTargetState::LiveOrUnknown => Err(error),
            }
        }
    }
}

async fn close_runtime_stdin(
    adapter: &RuntimeAdapter,
    task: &TaskIdentity,
    generation: Generation,
    exec_id: Option<&str>,
    target: &a3s_oci_sdk::ProcessTarget,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<StdinPumpOutcome, RuntimeError> {
    let close = cancellable_request(
        cancelled,
        "close runtime stdin after draining the containerd FIFO",
        adapter.close_stdin(task, generation, exec_id),
    )
    .await;
    match close {
        Ok(Some(())) => Ok(StdinPumpOutcome::Drained),
        Ok(None) => Ok(StdinPumpOutcome::Stopped),
        Err(error) => {
            match stdin_target_state(adapter, task, generation, target, &error, cancelled).await {
                StdinTargetState::Exited => Ok(StdinPumpOutcome::Drained),
                StdinTargetState::Stopped => Ok(StdinPumpOutcome::Stopped),
                StdinTargetState::LiveOrUnknown => Err(error),
            }
        }
    }
}

async fn stdin_target_state(
    adapter: &RuntimeAdapter,
    task: &TaskIdentity,
    generation: Generation,
    target: &a3s_oci_sdk::ProcessTarget,
    error: &RuntimeError,
    cancelled: &mut watch::Receiver<bool>,
) -> StdinTargetState {
    if !matches!(
        error.code,
        ErrorCode::FailedPrecondition | ErrorCode::NotFound
    ) {
        return StdinTargetState::LiveOrUnknown;
    }
    match cancellable_request(
        cancelled,
        "confirm runtime process exit after late containerd stdin",
        adapter.processes(task, generation),
    )
    .await
    {
        Ok(Some(processes)) if late_process_io_can_be_ignored(error, &processes, target) => {
            StdinTargetState::Exited
        }
        Ok(Some(_)) => StdinTargetState::LiveOrUnknown,
        Ok(None) => StdinTargetState::Stopped,
        Err(inventory_error) => {
            log::warn!(
                "could not confirm process exit after late containerd stdin: {inventory_error}"
            );
            StdinTargetState::LiveOrUnknown
        }
    }
}

pub(crate) fn late_process_io_can_be_ignored(
    error: &RuntimeError,
    processes: &[a3s_oci_sdk::ProcessRecord],
    target: &a3s_oci_sdk::ProcessTarget,
) -> bool {
    matches!(
        error.code,
        ErrorCode::FailedPrecondition | ErrorCode::NotFound
    ) && !processes.iter().any(|process| &process.target == target)
}

async fn pump_output(
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
            if chunk.sequence <= cursor {
                return Err(RuntimeError::new(
                    ErrorCode::Internal,
                    format!(
                        "runtime output cursor did not advance: received {}, current {cursor}",
                        chunk.sequence
                    ),
                )
                .for_operation("containerd-stdio"));
            }
            let next_cursor = chunk.sequence;
            match chunk.stream {
                OutputStream::Stdout => {
                    if !chunk.data.is_empty() {
                        if let Some(fifo) = &endpoints.stdout {
                            write_all(fifo, &chunk.data, &mut cancelled).await?;
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
                OutputStream::Stderr if endpoints.terminal => {
                    return Err(RuntimeError::new(
                        ErrorCode::Internal,
                        "runtime returned a separate stderr stream for terminal I/O",
                    )
                    .for_operation("containerd-stdio"));
                }
                OutputStream::Stderr => {
                    if !chunk.data.is_empty() {
                        if let Some(fifo) = &endpoints.stderr {
                            write_all(fifo, &chunk.data, &mut cancelled).await?;
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
            if let Some(committer) = &endpoints.cursor_committer {
                committer.commit(next_cursor).await?;
            }
            cursor = next_cursor;
        }
    }
    Ok(())
}

async fn cancellable_request<T>(
    cancelled: &mut watch::Receiver<bool>,
    operation: &str,
    request: impl std::future::Future<Output = Result<T, RuntimeError>>,
) -> Result<Option<T>, RuntimeError> {
    tokio::select! {
        changed = cancelled.changed() => {
            if changed.is_err() || *cancelled.borrow() {
                Ok(None)
            } else {
                Err(RuntimeError::new(
                    ErrorCode::Internal,
                    format!("{operation} received an unexpected cancellation state change"),
                )
                .for_operation("containerd-stdio"))
            }
        }
        result = tokio::time::timeout(PUMP_REQUEST_TIMEOUT, request) => {
            match result {
                Ok(result) => result.map(Some),
                Err(_) => Err(RuntimeError::new(
                    ErrorCode::DeadlineExceeded,
                    format!("{operation} exceeded {} seconds", PUMP_REQUEST_TIMEOUT.as_secs()),
                )
                .for_operation("containerd-stdio")
                .retryable(true)),
            }
        }
    }
}

async fn write_all(
    fifo: &AsyncFd<File>,
    mut bytes: &[u8],
    cancelled: &mut watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    while !bytes.is_empty() {
        let written = tokio::select! {
            changed = cancelled.changed() => {
                if changed.is_err() || *cancelled.borrow() {
                    return Ok(());
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
        bytes = &bytes[written..];
    }
    Ok(())
}

fn open_fifo(path: &str, read: bool, write: bool) -> Result<AsyncFd<File>, RuntimeError> {
    let path = Path::new(path);
    let file = OpenOptions::new()
        .read(read)
        .write(write)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io_error(format!("open containerd FIFO {}", path.display()), error))?;
    AsyncFd::new(file).map_err(|error| {
        io_error(
            format!("register containerd FIFO {}", path.display()),
            error,
        )
    })
}

fn open_output_fifo(path: &str) -> Result<AsyncFd<File>, RuntimeError> {
    // Keep one local read end so a restarted shim can reopen the writer before
    // containerd reconnects its reader. The shim never consumes this handle;
    // bytes remain available for containerd's external read end.
    open_fifo(path, true, true)
}

fn io_error(context: impl AsRef<str>, error: io::Error) -> RuntimeError {
    RuntimeError::new(
        if matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
        ) {
            ErrorCode::InvalidArgument
        } else {
            ErrorCode::Unavailable
        },
        format!("{}: {error}", context.as_ref()),
    )
    .for_operation("containerd-stdio")
}

trait OpenOptionsExt {
    fn custom_flags(&mut self, flags: i32) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    fn custom_flags(&mut self, flags: i32) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::custom_flags(self, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CapturedStdin {
        bytes: Vec<u8>,
        close_calls: usize,
        write_after_close: bool,
    }

    #[derive(Clone)]
    struct BlockingStdinService {
        captured: std::sync::Arc<std::sync::Mutex<CapturedStdin>>,
        write_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        completed_writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        write_started: std::sync::Arc<tokio::sync::Notify>,
        producer_finished: std::sync::Arc<std::sync::atomic::AtomicBool>,
        producer_finished_notify: std::sync::Arc<tokio::sync::Notify>,
        write_gate: std::sync::Arc<tokio::sync::Semaphore>,
    }

    impl Default for BlockingStdinService {
        fn default() -> Self {
            Self {
                captured: std::sync::Arc::default(),
                write_calls: std::sync::Arc::default(),
                completed_writes: std::sync::Arc::default(),
                write_started: std::sync::Arc::default(),
                producer_finished: std::sync::Arc::default(),
                producer_finished_notify: std::sync::Arc::default(),
                write_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
            }
        }
    }

    impl BlockingStdinService {
        async fn wait_for_first_write(&self) {
            loop {
                let notified = self.write_started.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.write_calls.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                    return;
                }
                notified.await;
            }
        }

        fn release_writes(&self, count: usize) {
            self.write_gate.add_permits(count);
        }

        fn mark_producer_finished(&self) {
            self.producer_finished
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.producer_finished_notify.notify_waiters();
        }

        async fn wait_for_producer_or_another_write(&self, current_calls: usize) {
            loop {
                let write_started = self.write_started.notified();
                let producer_finished = self.producer_finished_notify.notified();
                tokio::pin!(write_started);
                tokio::pin!(producer_finished);
                write_started.as_mut().enable();
                producer_finished.as_mut().enable();
                if self
                    .producer_finished
                    .load(std::sync::atomic::Ordering::SeqCst)
                    || self.write_calls.load(std::sync::atomic::Ordering::SeqCst) > current_calls
                {
                    return;
                }
                tokio::select! {
                    () = write_started => {}
                    () = producer_finished => {}
                }
            }
        }
    }

    #[derive(Clone, Default)]
    struct OutputReplayService {
        requested_cursors: Arc<std::sync::Mutex<Vec<u64>>>,
    }

    #[a3s_oci_sdk::async_trait]
    impl a3s_oci_sdk::OciRuntimeService for OutputReplayService {
        async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
            Err(RuntimeError::unsupported("test-features"))
        }

        async fn create(
            &self,
            _request: a3s_oci_sdk::CreateRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-create"))
        }

        async fn state(
            &self,
            _request: a3s_oci_sdk::StateRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-state"))
        }

        async fn start(
            &self,
            _request: a3s_oci_sdk::StartRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-start"))
        }

        async fn kill(
            &self,
            _request: a3s_oci_sdk::KillRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-kill"))
        }

        async fn delete(&self, _request: a3s_oci_sdk::DeleteRequest) -> a3s_oci_sdk::Result<()> {
            Err(RuntimeError::unsupported("test-delete"))
        }

        async fn read_output(
            &self,
            request: a3s_oci_sdk::ReadOutputRequest,
        ) -> a3s_oci_sdk::Result<Vec<a3s_oci_sdk::OutputChunk>> {
            let mut requested = self
                .requested_cursors
                .lock()
                .expect("requested output cursors");
            requested.push(request.after_sequence);
            if requested.len() != 1 || request.after_sequence != 5 {
                return Err(RuntimeError::new(
                    ErrorCode::Conflict,
                    format!(
                        "output replay started from cursor {}, expected persisted cursor 5",
                        request.after_sequence
                    ),
                ));
            }
            Ok(vec![
                a3s_oci_sdk::OutputChunk {
                    sequence: 8,
                    stream: OutputStream::Stdout,
                    data: b"new".to_vec(),
                    eof: false,
                },
                a3s_oci_sdk::OutputChunk {
                    sequence: 9,
                    stream: OutputStream::Stdout,
                    data: Vec::new(),
                    eof: true,
                },
            ])
        }
    }

    struct GatedCursorCommitter {
        cursors: std::sync::Mutex<Vec<u64>>,
        notified: tokio::sync::Notify,
        permits: tokio::sync::Semaphore,
    }

    impl GatedCursorCommitter {
        fn new() -> Self {
            Self {
                cursors: std::sync::Mutex::new(Vec::new()),
                notified: tokio::sync::Notify::new(),
                permits: tokio::sync::Semaphore::new(0),
            }
        }

        async fn wait_for_commits(&self, expected: usize) {
            loop {
                let notified = self.notified.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.cursors.lock().expect("committed cursors").len() >= expected {
                    return;
                }
                notified.await;
            }
        }

        fn release_commit(&self) {
            self.permits.add_permits(1);
        }
    }

    #[async_trait]
    impl OutputCursorCommitter for GatedCursorCommitter {
        async fn commit(&self, cursor: u64) -> Result<(), RuntimeError> {
            self.cursors.lock().expect("committed cursors").push(cursor);
            self.notified.notify_waiters();
            self.permits
                .acquire()
                .await
                .expect("cursor commit permit")
                .forget();
            Ok(())
        }
    }

    #[a3s_oci_sdk::async_trait]
    impl a3s_oci_sdk::OciRuntimeService for BlockingStdinService {
        async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
            Err(RuntimeError::unsupported("test-features"))
        }

        async fn create(
            &self,
            _request: a3s_oci_sdk::CreateRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-create"))
        }

        async fn state(
            &self,
            _request: a3s_oci_sdk::StateRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-state"))
        }

        async fn start(
            &self,
            _request: a3s_oci_sdk::StartRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-start"))
        }

        async fn kill(
            &self,
            _request: a3s_oci_sdk::KillRequest,
        ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerRecord> {
            Err(RuntimeError::unsupported("test-kill"))
        }

        async fn delete(&self, _request: a3s_oci_sdk::DeleteRequest) -> a3s_oci_sdk::Result<()> {
            Err(RuntimeError::unsupported("test-delete"))
        }

        async fn write_stdin(
            &self,
            request: a3s_oci_sdk::WriteStdinRequest,
        ) -> a3s_oci_sdk::Result<()> {
            self.write_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.write_started.notify_waiters();
            self.write_gate
                .acquire()
                .await
                .expect("stdin write gate")
                .forget();
            let mut captured = self.captured.lock().expect("captured stdin");
            captured.write_after_close |= captured.close_calls != 0;
            captured.bytes.extend_from_slice(&request.data);
            self.completed_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn close_stdin(
            &self,
            _request: a3s_oci_sdk::CloseStdinRequest,
        ) -> a3s_oci_sdk::Result<()> {
            assert!(
                self.producer_finished
                    .load(std::sync::atomic::Ordering::SeqCst),
                "runtime stdin closed before the containerd producer completed"
            );
            self.captured.lock().expect("captured stdin").close_calls += 1;
            Ok(())
        }
    }

    fn process_target() -> a3s_oci_sdk::ProcessTarget {
        a3s_oci_sdk::ProcessTarget {
            container: a3s_oci_sdk::ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("late-stdin-test").expect("container ID"),
                Generation(7),
            ),
            process_id: a3s_oci_sdk::ProcessId::init(),
        }
    }

    #[test]
    fn cancellation_is_replay_safe() {
        let cancellation = PumpCancellation::new();
        let receiver = cancellation.subscribe();
        assert!(!*receiver.borrow());
        cancellation.cancel();
        cancellation.cancel();
        assert!(*receiver.borrow());
    }

    #[test]
    fn terminal_io_rejects_a_separate_stderr_fifo() {
        let error = validate_process_io_endpoints(&ProcessIoEndpoints {
            stdin: "stdin",
            stdout: "stdout",
            stderr: "stderr",
            terminal: true,
            await_start_activation: true,
            output_cursor: 0,
            output_cursor_committer: None,
        })
        .expect_err("terminal stderr must fail closed");

        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn late_stdin_is_ignored_only_after_the_exact_process_exits() {
        let target = process_target();
        let still_live = a3s_oci_sdk::ProcessRecord {
            target: target.clone(),
            pid: Some(4242),
            terminal: true,
        };
        let stopped = RuntimeError::new(ErrorCode::FailedPrecondition, "process stopped");
        let unrelated = RuntimeError::new(ErrorCode::Internal, "transport failed");

        assert!(!late_process_io_can_be_ignored(
            &stopped,
            std::slice::from_ref(&still_live),
            &target,
        ));
        assert!(late_process_io_can_be_ignored(&stopped, &[], &target));
        assert!(!late_process_io_can_be_ignored(&unrelated, &[], &target));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn output_pump_resumes_after_persisted_cursor_and_commits_after_fifo_write() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stdout");
        let path_c =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );
        let reader = open_fifo(path.to_str().expect("UTF-8 FIFO path"), true, false)
            .expect("open output reader");
        let runtime = OutputReplayService::default();
        let requested_cursors = runtime.requested_cursors.clone();
        let adapter = RuntimeAdapter::from_client(
            a3s_oci_sdk::RuntimeClient::new(runtime),
            a3s_oci_sdk::IsolationRequest::SharedHostKernel,
        );
        let committer = Arc::new(GatedCursorCommitter::new());
        let identity = TaskIdentity::new("k8s.io", "restored-output").expect("task identity");
        let pumps = start_process_pumps(
            adapter,
            identity,
            Generation(7),
            None,
            ProcessIoEndpoints {
                stdin: "",
                stdout: path.to_str().expect("UTF-8 FIFO path"),
                stderr: "",
                terminal: true,
                await_start_activation: false,
                output_cursor: 5,
                output_cursor_committer: Some(committer.clone()),
            },
        )
        .expect("start restored output pump");

        tokio::time::timeout(Duration::from_secs(1), committer.wait_for_commits(1))
            .await
            .expect("first cursor commit deadline");
        let mut guard = tokio::time::timeout(Duration::from_secs(1), reader.readable())
            .await
            .expect("output FIFO readable deadline")
            .expect("output FIFO readable");
        let mut bytes = [0_u8; 3];
        let read = guard
            .try_io(|handle| handle.get_ref().read(&mut bytes))
            .expect("output readiness")
            .expect("read output bytes");
        assert_eq!(read, bytes.len());
        assert_eq!(&bytes, b"new");
        drop(guard);
        assert_eq!(
            *requested_cursors.lock().expect("requested cursors"),
            vec![5]
        );
        assert_eq!(
            *committer.cursors.lock().expect("committed cursors"),
            vec![8]
        );

        committer.release_commit();
        tokio::time::timeout(Duration::from_secs(1), committer.wait_for_commits(2))
            .await
            .expect("EOF cursor commit deadline");
        assert_eq!(
            *committer.cursors.lock().expect("committed cursors"),
            vec![8, 9]
        );
        committer.release_commit();
        pumps.stop().await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn fifo_wrapper_opens_a_real_fifo_nonblocking() {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stdio");
        let path_bytes = path.as_os_str().as_bytes();
        let path = std::ffi::CString::new(path_bytes).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );
        let handle = open_fifo(path.to_str().expect("UTF-8 path"), true, false)
            .expect("open nonblocking FIFO");
        assert!(handle.get_ref().as_raw_fd() >= 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn stdin_fifo_distinguishes_writer_connection_from_real_eof() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stdin");
        let path_bytes = path.as_os_str().as_bytes();
        let path_c = std::ffi::CString::new(path_bytes).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );

        let fifo = open_fifo(path.to_str().expect("UTF-8 path"), true, false)
            .expect("open nonblocking FIFO");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fifo.readable())
                .await
                .is_err(),
            "a FIFO without a writer must not be mistaken for EOF"
        );

        let writer = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .expect("open FIFO writer");
        (&writer).write_all(b"x").expect("write FIFO byte");
        let mut guard = tokio::time::timeout(Duration::from_secs(1), fifo.readable())
            .await
            .expect("FIFO becomes readable")
            .expect("readable guard");
        let mut byte = [0_u8; 1];
        assert_eq!(
            guard
                .try_io(|handle| handle.get_ref().read(&mut byte))
                .expect("data readiness")
                .expect("read FIFO byte"),
            1
        );
        assert_eq!(byte[0], b'x');
        drop(guard);

        drop(writer);
        let mut guard = tokio::time::timeout(Duration::from_secs(1), fifo.readable())
            .await
            .expect("FIFO EOF becomes readable")
            .expect("readable guard");
        assert_eq!(
            guard
                .try_io(|handle| handle.get_ref().read(&mut byte))
                .expect("EOF readiness")
                .expect("read EOF"),
            0
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn initial_empty_stdin_closes_at_the_successful_start_boundary() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("empty-stdin");
        let path_c =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );

        let service = BlockingStdinService::default();
        service.mark_producer_finished();
        let adapter = RuntimeAdapter::from_client(
            a3s_oci_sdk::RuntimeClient::new(service.clone()),
            a3s_oci_sdk::IsolationRequest::SharedHostKernel,
        );
        let identity = TaskIdentity::new("k8s.io", "empty-stdin").expect("task identity");
        let mut pumps = start_process_pumps(
            adapter,
            identity,
            Generation(7),
            None,
            ProcessIoEndpoints {
                stdin: path.to_str().expect("UTF-8 FIFO path"),
                stdout: "",
                stderr: "",
                terminal: false,
                await_start_activation: true,
                output_cursor: 0,
                output_cursor_committer: None,
            },
        )
        .expect("start stdin pump");
        let drain = pumps.stdin_drain().expect("stdin drain handle");

        pumps.activate_stdin();
        pumps.activate_stdin();
        let mut completion = drain;
        tokio::time::timeout(Duration::from_secs(1), completion.wait_for_completion())
            .await
            .expect("empty stdin close deadline")
            .expect("empty stdin close");
        {
            let captured = service.captured.lock().expect("captured stdin");
            assert!(captured.bytes.is_empty());
            assert_eq!(captured.close_calls, 1);
        }
        assert!(pumps.failure().is_none());
        pumps.stop().await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn connected_slow_stdin_is_not_mistaken_for_initial_eof() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("slow-stdin");
        let path_c =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );

        let service = BlockingStdinService::default();
        service.release_writes(16);
        let adapter = RuntimeAdapter::from_client(
            a3s_oci_sdk::RuntimeClient::new(service.clone()),
            a3s_oci_sdk::IsolationRequest::SharedHostKernel,
        );
        let identity = TaskIdentity::new("k8s.io", "slow-stdin").expect("task identity");
        let mut pumps = start_process_pumps(
            adapter,
            identity,
            Generation(7),
            None,
            ProcessIoEndpoints {
                stdin: path.to_str().expect("UTF-8 FIFO path"),
                stdout: "",
                stderr: "",
                terminal: false,
                await_start_activation: true,
                output_cursor: 0,
                output_cursor_committer: None,
            },
        )
        .expect("start stdin pump");
        let drain = pumps.stdin_drain().expect("stdin drain handle");
        let writer = open_fifo(path.to_str().expect("UTF-8 FIFO path"), false, true)
            .expect("connect stdin writer before Start activation");

        pumps.activate_stdin();
        let mut completion = drain.clone();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), completion.wait_for_completion())
                .await
                .is_err(),
            "a connected writer with no bytes yet must keep stdin open"
        );
        assert_eq!(
            service.captured.lock().expect("captured stdin").close_calls,
            0,
            "a connected writer with no bytes yet must keep stdin open"
        );
        let cancellation = PumpCancellation::new();
        let mut receiver = cancellation.subscribe();
        write_all(&writer, b"delayed", &mut receiver)
            .await
            .expect("write delayed stdin");
        service.mark_producer_finished();
        drain.request_and_wait().await.expect("drain delayed stdin");
        {
            let captured = service.captured.lock().expect("captured stdin");
            assert_eq!(captured.bytes, b"delayed");
            assert_eq!(captured.close_calls, 1);
        }
        assert!(pumps.failure().is_none());
        pumps.stop().await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn restored_stdin_waits_for_a_real_producer_reconnect() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("restored-stdin");
        let path_c =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );

        let service = BlockingStdinService::default();
        service.release_writes(16);
        let adapter = RuntimeAdapter::from_client(
            a3s_oci_sdk::RuntimeClient::new(service.clone()),
            a3s_oci_sdk::IsolationRequest::SharedHostKernel,
        );
        let identity = TaskIdentity::new("k8s.io", "restored-stdin").expect("task identity");
        let mut pumps = start_process_pumps(
            adapter,
            identity,
            Generation(7),
            None,
            ProcessIoEndpoints {
                stdin: path.to_str().expect("UTF-8 FIFO path"),
                stdout: "",
                stderr: "",
                terminal: false,
                await_start_activation: false,
                output_cursor: 0,
                output_cursor_committer: None,
            },
        )
        .expect("restore stdin pump");
        let drain = pumps.stdin_drain().expect("stdin drain handle");

        // Start replay must not activate a rehydrated pump. Only a real FIFO
        // reconnect or an explicit CloseIO request can establish its EOF.
        pumps.activate_stdin();
        let mut completion = drain.clone();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), completion.wait_for_completion())
                .await
                .is_err(),
            "a restored pump must not invent EOF while its producer is absent"
        );
        assert_eq!(
            service.captured.lock().expect("captured stdin").close_calls,
            0
        );

        let writer = open_fifo(path.to_str().expect("UTF-8 FIFO path"), false, true)
            .expect("reconnect restored stdin writer");
        let cancellation = PumpCancellation::new();
        let mut receiver = cancellation.subscribe();
        write_all(&writer, b"restored", &mut receiver)
            .await
            .expect("write restored stdin");
        service.mark_producer_finished();
        drain
            .request_and_wait()
            .await
            .expect("drain restored stdin");
        {
            let captured = service.captured.lock().expect("captured stdin");
            assert_eq!(captured.bytes, b"restored");
            assert_eq!(captured.close_calls, 1);
        }
        assert!(pumps.failure().is_none());
        pumps.stop().await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn close_io_waits_for_every_buffered_stdin_byte_before_eof() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stdin-drain");
        let path_c =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );

        let service = BlockingStdinService::default();
        let adapter = RuntimeAdapter::from_client(
            a3s_oci_sdk::RuntimeClient::new(service.clone()),
            a3s_oci_sdk::IsolationRequest::SharedHostKernel,
        );
        let identity = TaskIdentity::new("k8s.io", "stdin-drain").expect("task identity");
        let mut pumps = start_process_pumps(
            adapter,
            identity,
            Generation(7),
            None,
            ProcessIoEndpoints {
                stdin: path.to_str().expect("UTF-8 FIFO path"),
                stdout: "",
                stderr: "",
                terminal: false,
                await_start_activation: true,
                output_cursor: 0,
                output_cursor_committer: None,
            },
        )
        .expect("start stdin pump");
        let drain = pumps.stdin_drain().expect("stdin drain handle");
        let payload = (0..(FIFO_BUFFER_BYTES * 3 + 17))
            .map(|index| u8::try_from(index % 251).expect("bounded byte"))
            .collect::<Vec<_>>();
        let expected = payload.clone();
        let writer = open_fifo(path.to_str().expect("UTF-8 FIFO path"), false, true)
            .expect("open nonblocking FIFO writer");
        let writer_service = service.clone();
        let writer = tokio::spawn(async move {
            let cancellation = PumpCancellation::new();
            let mut receiver = cancellation.subscribe();
            write_all(&writer, &payload, &mut receiver)
                .await
                .expect("write complete payload");
            writer_service.mark_producer_finished();
        });

        pumps.activate_stdin();
        service.wait_for_first_write().await;
        while !service
            .producer_finished
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            let current_calls = service
                .write_calls
                .load(std::sync::atomic::Ordering::SeqCst);
            service.release_writes(1);
            service
                .wait_for_producer_or_another_write(current_calls)
                .await;
        }
        assert!(
            service
                .write_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                > service
                    .completed_writes
                    .load(std::sync::atomic::Ordering::SeqCst),
            "the producer must finish while an SDK write remains backpressured"
        );
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .expect("FIFO writer deadline")
            .expect("FIFO writer task");
        let mut close_io = tokio::spawn(drain.request_and_wait());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut close_io)
                .await
                .is_err(),
            "CloseIO must wait for the backpressured write and buffered FIFO bytes"
        );
        service.release_writes(1024);
        tokio::time::timeout(Duration::from_secs(5), close_io)
            .await
            .expect("stdin drain deadline")
            .expect("stdin drain task")
            .expect("stdin drain result");
        {
            let captured = service.captured.lock().expect("captured stdin");
            assert_eq!(captured.bytes, expected);
            assert_eq!(captured.close_calls, 1);
            assert!(!captured.write_after_close);
        }
        assert!(pumps.failure().is_none());
        pumps.stop().await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn output_fifo_survives_a_containerd_reader_reconnect_window() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stdout");
        let path_c =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path without NUL");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create test FIFO: {}",
            io::Error::last_os_error()
        );

        let output = open_output_fifo(path.to_str().expect("UTF-8 path"))
            .expect("open output before external reader");
        output
            .get_ref()
            .write_all(b"replayed")
            .expect("write while external reader is absent");
        let mut reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .expect("reconnect output reader");
        let mut bytes = [0_u8; 8];

        assert_eq!(reader.read(&mut bytes).expect("read replayed output"), 8);
        assert_eq!(&bytes, b"replayed");
    }
}
