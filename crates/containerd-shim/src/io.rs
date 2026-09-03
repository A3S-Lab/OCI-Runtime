use std::fs::File;
use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_sdk::{Error as RuntimeError, ErrorCode, Generation, OutputStream};
use async_trait::async_trait;
use tokio::io::{unix::AsyncFd, Interest};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::adapter::{ExecIdentity, RuntimeAdapter, TaskIdentity};
use crate::metadata::{PendingStdinWrite, StdinCloseState};

mod fifo;
mod output;

use fifo::{io_error, open_fifo, open_output_fifo};
use output::{pump_output, OutputPumpEndpoints};
#[cfg(test)]
use output::{validate_output_chunk, validate_output_stream_state};

const FIFO_BUFFER_BYTES: usize = 64 * 1024;
const OUTPUT_READ_BYTES: u32 = 64 * 1024;
const _: () = assert!(FIFO_BUFFER_BYTES <= a3s_oci_sdk::MAX_STDIN_WRITE_BYTES);
const _: () = assert!(OUTPUT_READ_BYTES <= a3s_oci_sdk::MAX_OUTPUT_READ_BYTES);
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

struct StdinCloseRequest<'a> {
    adapter: &'a RuntimeAdapter,
    task: &'a TaskIdentity,
    generation: Generation,
    exec_id: Option<&'a ExecIdentity>,
    target: &'a a3s_oci_sdk::ProcessTarget,
    journal: Option<&'a dyn StdinJournal>,
}

struct RestoredStdinClose {
    adapter: RuntimeAdapter,
    task: TaskIdentity,
    generation: Generation,
    exec_id: Option<ExecIdentity>,
    target: a3s_oci_sdk::ProcessTarget,
    journal: Option<Arc<dyn StdinJournal>>,
}

pub(crate) struct ProcessIoEndpoints<'a> {
    pub(crate) stdin: &'a str,
    pub(crate) stdout: &'a str,
    pub(crate) stderr: &'a str,
    pub(crate) terminal: bool,
    pub(crate) await_start_activation: bool,
    pub(crate) read_stdin_at_activation: bool,
    pub(crate) stdin_sequence: u64,
    pub(crate) pending_stdin_write: Option<PendingStdinWrite>,
    pub(crate) stdin_close_state: StdinCloseState,
    pub(crate) stdin_journal: Option<Arc<dyn StdinJournal>>,
    pub(crate) output_cursor: u64,
    pub(crate) output_cursor_committer: Option<Arc<dyn OutputCursorCommitter>>,
}

#[async_trait]
pub(crate) trait OutputCursorCommitter: Send + Sync {
    async fn commit(&self, cursor: u64) -> Result<(), RuntimeError>;
}

#[async_trait]
pub(crate) trait StdinJournal: Send + Sync {
    async fn prepare(&self, sequence: u64, data: Vec<u8>) -> Result<(), RuntimeError>;

    async fn commit(&self, sequence: u64) -> Result<(), RuntimeError>;

    async fn prepare_close(&self) -> Result<(), RuntimeError>;

    async fn commit_close(&self) -> Result<(), RuntimeError>;
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
    exec_id: Option<ExecIdentity>,
    endpoints: ProcessIoEndpoints<'_>,
) -> Result<ProcessPumps, RuntimeError> {
    validate_process_io_endpoints(&endpoints)?;
    let target = adapter.process_target(&task, generation, exec_id.as_ref())?;
    let cancellation = PumpCancellation::new();
    let (failure_sender, failures) = mpsc::unbounded_channel();
    let mut tasks = Vec::new();
    let mut stdin_drain = None;
    if !endpoints.stdin.is_empty() {
        let (drain_request, drain_requested) = watch::channel(false);
        let (activation_request, activation_requested) = if endpoints.await_start_activation {
            let (request, requested) = watch::channel(false);
            (Some(request), Some(requested))
        } else {
            (None, None)
        };
        let (task_handle, drain) = match endpoints.stdin_close_state {
            StdinCloseState::Open => {
                let fifo = open_fifo(endpoints.stdin, true, false)?;
                spawn_stdin_pump(
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
                        endpoints.read_stdin_at_activation,
                        endpoints.stdin_sequence,
                        endpoints.pending_stdin_write,
                        endpoints.stdin_journal,
                    ),
                )
            }
            StdinCloseState::Closing => spawn_stdin_pump(
                failure_sender.clone(),
                drain_request,
                activation_request,
                finish_stdin_close(
                    RestoredStdinClose {
                        adapter: adapter.clone(),
                        task,
                        generation,
                        exec_id,
                        target: target.clone(),
                        journal: endpoints.stdin_journal,
                    },
                    cancellation.subscribe(),
                    drain_requested,
                    activation_requested,
                ),
            ),
            StdinCloseState::Closed => spawn_stdin_pump(
                failure_sender.clone(),
                drain_request,
                activation_request,
                async { Ok(StdinPumpOutcome::Drained) },
            ),
        };
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
    if endpoints.read_stdin_at_activation && !endpoints.await_start_activation {
        return Err(RuntimeError::new(
            ErrorCode::InvalidArgument,
            "containerd stdin cannot read at activation without an activation gate",
        )
        .for_operation("containerd-stdio"));
    }
    if endpoints.terminal && !endpoints.stderr.is_empty() {
        return Err(RuntimeError::new(
            ErrorCode::InvalidArgument,
            "containerd terminal I/O must use one merged stdout stream and omit stderr",
        )
        .for_operation("containerd-stdio"));
    }
    if endpoints.stdin.is_empty()
        && (endpoints.stdin_sequence != 0
            || endpoints.pending_stdin_write.is_some()
            || endpoints.stdin_close_state != StdinCloseState::Open)
    {
        return Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "containerd stdin journal state requires a configured stdin FIFO",
        )
        .for_operation("containerd-stdio"));
    }
    if endpoints.stdin_close_state != StdinCloseState::Open
        && endpoints.pending_stdin_write.is_some()
    {
        return Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "containerd stdin cannot retain a pending write after close has started",
        )
        .for_operation("containerd-stdio"));
    }
    if (endpoints.stdin_sequence != 0
        || endpoints.pending_stdin_write.is_some()
        || endpoints.stdin_close_state != StdinCloseState::Open)
        && endpoints.stdin_journal.is_none()
    {
        return Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "containerd stdin recovery state requires a durable journal",
        )
        .for_operation("containerd-stdio"));
    }
    if (!endpoints.stdout.is_empty() || (!endpoints.terminal && !endpoints.stderr.is_empty()))
        && endpoints.output_cursor_committer.is_none()
    {
        return Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "containerd output FIFO delivery requires a durable byte-cursor committer",
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
    exec_id: Option<ExecIdentity>,
    target: a3s_oci_sdk::ProcessTarget,
    fifo: AsyncFd<File>,
    mut cancelled: watch::Receiver<bool>,
    mut drain_requested: watch::Receiver<bool>,
    mut activation_requested: Option<watch::Receiver<bool>>,
    read_stdin_at_activation: bool,
    initial_sequence: u64,
    pending_stdin_write: Option<PendingStdinWrite>,
    stdin_journal: Option<Arc<dyn StdinJournal>>,
) -> Result<StdinPumpOutcome, RuntimeError> {
    let mut sequence = initial_sequence;
    let mut buffer = vec![0_u8; FIFO_BUFFER_BYTES];
    let startup = if let Some(activation) = &mut activation_requested {
        Some(wait_for_stdin_activation(activation, &mut cancelled, &mut drain_requested).await?)
    } else {
        None
    };
    if matches!(startup, Some(StdinStartup::Stopped)) {
        return Ok(StdinPumpOutcome::Stopped);
    }
    if let Some(pending) = pending_stdin_write {
        replay_stdin_write(
            &adapter,
            &task,
            generation,
            exec_id.as_ref(),
            &target,
            &mut sequence,
            &pending,
            stdin_journal.as_deref(),
            &mut cancelled,
        )
        .await?;
    }
    if let Some(startup) = startup {
        match startup {
            StdinStartup::Activated if read_stdin_at_activation => {
                match read_fifo_nonblocking(fifo.get_ref(), &mut buffer)? {
                    FifoRead::Bytes(length) => {
                        write_stdin_chunk(
                            &adapter,
                            &task,
                            generation,
                            exec_id.as_ref(),
                            &target,
                            &mut sequence,
                            &buffer[..length],
                            stdin_journal.as_deref(),
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
                            StdinCloseRequest {
                                adapter: &adapter,
                                task: &task,
                                generation,
                                exec_id: exec_id.as_ref(),
                                target: &target,
                                journal: stdin_journal.as_deref(),
                            },
                            true,
                            &mut cancelled,
                        )
                        .await;
                    }
                }
            }
            StdinStartup::Activated | StdinStartup::DrainRequested => {}
            StdinStartup::Stopped => return Err(stopped_stdin_startup_error()),
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
                        exec_id.as_ref(),
                        &target,
                        &mut sequence,
                        &buffer[..length],
                        stdin_journal.as_deref(),
                        &mut cancelled,
                    )
                    .await?;
                    continue;
                }
                FifoRead::Empty | FifoRead::Eof => {
                    return close_runtime_stdin(
                        StdinCloseRequest {
                            adapter: &adapter,
                            task: &task,
                            generation,
                            exec_id: exec_id.as_ref(),
                            target: &target,
                            journal: stdin_journal.as_deref(),
                        },
                        true,
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
                StdinCloseRequest {
                    adapter: &adapter,
                    task: &task,
                    generation,
                    exec_id: exec_id.as_ref(),
                    target: &target,
                    journal: stdin_journal.as_deref(),
                },
                true,
                &mut cancelled,
            )
            .await;
        }
        write_stdin_chunk(
            &adapter,
            &task,
            generation,
            exec_id.as_ref(),
            &target,
            &mut sequence,
            &buffer[..length],
            stdin_journal.as_deref(),
            &mut cancelled,
        )
        .await?;
    }
}

fn stopped_stdin_startup_error() -> RuntimeError {
    RuntimeError::new(
        ErrorCode::Internal,
        "stdin pump reached the stopped startup state after its activation gate",
    )
    .for_operation("containerd-stdin")
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
    exec_id: Option<&ExecIdentity>,
    target: &a3s_oci_sdk::ProcessTarget,
    sequence: &mut u64,
    data: &[u8],
    stdin_journal: Option<&dyn StdinJournal>,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    let next_sequence = sequence.checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            ErrorCode::ResourceExhausted,
            "containerd stdin pump sequence space is exhausted",
        )
        .for_operation("containerd-stdin")
    })?;
    dispatch_stdin_write(
        adapter,
        task,
        generation,
        exec_id,
        target,
        next_sequence,
        data,
        stdin_journal,
        true,
        cancelled,
    )
    .await?;
    *sequence = next_sequence;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn replay_stdin_write(
    adapter: &RuntimeAdapter,
    task: &TaskIdentity,
    generation: Generation,
    exec_id: Option<&ExecIdentity>,
    target: &a3s_oci_sdk::ProcessTarget,
    sequence: &mut u64,
    pending: &PendingStdinWrite,
    stdin_journal: Option<&dyn StdinJournal>,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    let expected = sequence.checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            ErrorCode::ResourceExhausted,
            "containerd stdin pump sequence space is exhausted",
        )
        .for_operation("containerd-stdin")
    })?;
    if pending.sequence() != expected {
        return Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            format!(
                "pending containerd stdin sequence {} does not follow completed sequence {}",
                pending.sequence(),
                *sequence
            ),
        )
        .for_operation("containerd-stdin"));
    }
    dispatch_stdin_write(
        adapter,
        task,
        generation,
        exec_id,
        target,
        pending.sequence(),
        pending.data(),
        stdin_journal,
        false,
        cancelled,
    )
    .await?;
    *sequence = pending.sequence();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_stdin_write(
    adapter: &RuntimeAdapter,
    task: &TaskIdentity,
    generation: Generation,
    exec_id: Option<&ExecIdentity>,
    target: &a3s_oci_sdk::ProcessTarget,
    sequence: u64,
    data: &[u8],
    stdin_journal: Option<&dyn StdinJournal>,
    prepare: bool,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    let context = adapter.stdin_operation(task, exec_id, sequence)?;
    if prepare {
        if let Some(journal) = stdin_journal {
            journal.prepare(sequence, data.to_vec()).await?;
        }
    }
    let write = cancellable_request(
        cancelled,
        "write containerd stdin through the runtime SDK",
        adapter.write_stdin(target.clone(), context, data.to_vec()),
    )
    .await;
    match write {
        Ok(Some(())) => {}
        Ok(None) => {
            return Err(RuntimeError::new(
                ErrorCode::Unavailable,
                "containerd stdin pump stopped during an ordered write",
            )
            .for_operation("containerd-stdin")
            .retryable(true));
        }
        Err(error) => {
            match stdin_target_state(adapter, task, generation, target, &error, cancelled).await {
                StdinTargetState::Exited => {}
                StdinTargetState::Stopped => {
                    return Err(RuntimeError::new(
                        ErrorCode::Unavailable,
                        "containerd stdin pump stopped while confirming a late write",
                    )
                    .for_operation("containerd-stdin")
                    .retryable(true));
                }
                StdinTargetState::LiveOrUnknown => return Err(error),
            }
        }
    }
    if let Some(journal) = stdin_journal {
        journal.commit(sequence).await?;
    }
    Ok(())
}

async fn close_runtime_stdin(
    request: StdinCloseRequest<'_>,
    prepare: bool,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<StdinPumpOutcome, RuntimeError> {
    if prepare {
        if let Some(journal) = request.journal {
            journal.prepare_close().await?;
        }
    }
    let close = cancellable_request(
        cancelled,
        "close runtime stdin after draining the containerd FIFO",
        request
            .adapter
            .close_stdin(request.task, request.generation, request.exec_id),
    )
    .await;
    let outcome = match close {
        Ok(Some(())) => StdinPumpOutcome::Drained,
        Ok(None) => StdinPumpOutcome::Stopped,
        Err(error) => {
            match stdin_target_state(
                request.adapter,
                request.task,
                request.generation,
                request.target,
                &error,
                cancelled,
            )
            .await
            {
                StdinTargetState::Exited => StdinPumpOutcome::Drained,
                StdinTargetState::Stopped => StdinPumpOutcome::Stopped,
                StdinTargetState::LiveOrUnknown => return Err(error),
            }
        }
    };
    if outcome == StdinPumpOutcome::Drained {
        if let Some(journal) = request.journal {
            journal.commit_close().await?;
        }
    }
    Ok(outcome)
}

async fn finish_stdin_close(
    request: RestoredStdinClose,
    mut cancelled: watch::Receiver<bool>,
    mut drain_requested: watch::Receiver<bool>,
    mut activation_requested: Option<watch::Receiver<bool>>,
) -> Result<StdinPumpOutcome, RuntimeError> {
    if let Some(activation) = &mut activation_requested {
        let startup =
            wait_for_stdin_activation(activation, &mut cancelled, &mut drain_requested).await?;
        if startup == StdinStartup::Stopped {
            return Ok(StdinPumpOutcome::Stopped);
        }
    }
    close_runtime_stdin(
        StdinCloseRequest {
            adapter: &request.adapter,
            task: &request.task,
            generation: request.generation,
            exec_id: request.exec_id.as_ref(),
            target: &request.target,
            journal: request.journal.as_deref(),
        },
        false,
        &mut cancelled,
    )
    .await
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

#[cfg(test)]
mod tests;
