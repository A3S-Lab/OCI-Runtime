use super::*;
use std::io::Write;

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
            result = fifo.async_io(Interest::WRITABLE, |mut file| file.write(bytes)) => {
                result.map_err(|error| io_error("write test FIFO", error))?
            }
        };
        if written == 0 {
            return Err(io_error(
                "write test FIFO",
                io::Error::new(io::ErrorKind::WriteZero, "FIFO accepted zero bytes"),
            ));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

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
    payload: Option<Arc<[u8]>>,
}

impl OutputReplayService {
    fn with_payload(payload: Vec<u8>) -> Self {
        Self {
            requested_cursors: Arc::default(),
            payload: Some(Arc::from(payload)),
        }
    }
}

#[derive(Clone, Default)]
struct ReplaySafeStdinService {
    completed: Arc<std::sync::Mutex<std::collections::HashMap<a3s_oci_sdk::OperationId, Vec<u8>>>>,
    requests: Arc<std::sync::Mutex<Vec<a3s_oci_sdk::OperationId>>>,
    effects: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl ReplaySafeStdinService {
    fn with_completed(operation_id: a3s_oci_sdk::OperationId, data: Vec<u8>) -> Self {
        let mut completed = std::collections::HashMap::new();
        completed.insert(operation_id, data.clone());
        Self {
            completed: Arc::new(std::sync::Mutex::new(completed)),
            requests: Arc::default(),
            effects: Arc::new(std::sync::Mutex::new(vec![data])),
        }
    }
}

#[a3s_oci_sdk::async_trait]
impl a3s_oci_sdk::OciRuntimeService for ReplaySafeStdinService {
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
        let operation_id = request.context.operation_id;
        self.requests
            .lock()
            .expect("stdin requests")
            .push(operation_id.clone());
        let mut completed = self.completed.lock().expect("completed stdin writes");
        if let Some(previous) = completed.get(&operation_id) {
            if previous == &request.data {
                return Ok(());
            }
            return Err(RuntimeError::new(
                ErrorCode::Conflict,
                "stdin operation ID was reused with different data",
            ));
        }
        completed.insert(operation_id, request.data.clone());
        self.effects
            .lock()
            .expect("stdin effects")
            .push(request.data);
        Ok(())
    }

    async fn close_stdin(
        &self,
        _request: a3s_oci_sdk::CloseStdinRequest,
    ) -> a3s_oci_sdk::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordingStdinJournal {
    prepared: std::sync::Mutex<Vec<(u64, Vec<u8>)>>,
    committed: std::sync::Mutex<Vec<u64>>,
    close_prepares: std::sync::atomic::AtomicUsize,
    close_commits: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl StdinJournal for RecordingStdinJournal {
    async fn prepare(&self, sequence: u64, data: Vec<u8>) -> Result<(), RuntimeError> {
        self.prepared
            .lock()
            .expect("prepared stdin journal")
            .push((sequence, data));
        Ok(())
    }

    async fn commit(&self, sequence: u64) -> Result<(), RuntimeError> {
        self.committed
            .lock()
            .expect("committed stdin journal")
            .push(sequence);
        Ok(())
    }

    async fn prepare_close(&self) -> Result<(), RuntimeError> {
        self.close_prepares
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn commit_close(&self) -> Result<(), RuntimeError> {
        self.close_commits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
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
        if let Some(payload) = &self.payload {
            let start = usize::try_from(request.after_sequence).map_err(|_| {
                RuntimeError::new(
                    ErrorCode::ResourceExhausted,
                    "test output cursor does not fit usize",
                )
            })?;
            if start < payload.len() {
                let requested = usize::try_from(request.max_bytes).map_err(|_| {
                    RuntimeError::new(
                        ErrorCode::ResourceExhausted,
                        "test output byte limit does not fit usize",
                    )
                })?;
                let length = payload.len().saturating_sub(start).min(requested);
                let end = start.checked_add(length).ok_or_else(|| {
                    RuntimeError::new(
                        ErrorCode::ResourceExhausted,
                        "test output page range overflowed",
                    )
                })?;
                return Ok(vec![a3s_oci_sdk::OutputChunk {
                    sequence: request
                        .after_sequence
                        .checked_add(u64::try_from(length).expect("test output page length"))
                        .expect("test output cursor"),
                    stream: OutputStream::Stdout,
                    data: payload[start..end].to_vec(),
                    eof: false,
                }]);
            }
            if start == payload.len() {
                return Ok(vec![a3s_oci_sdk::OutputChunk {
                    sequence: request.after_sequence + 1,
                    stream: OutputStream::Stdout,
                    data: Vec::new(),
                    eof: true,
                }]);
            }
            return Err(RuntimeError::new(
                ErrorCode::Conflict,
                "test output cursor advanced beyond the payload",
            ));
        }
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
fn output_chunks_require_exact_byte_cursors_and_a_durable_committer() {
    let data = a3s_oci_sdk::OutputChunk {
        sequence: 3,
        stream: OutputStream::Stdout,
        data: b"abc".to_vec(),
        eof: false,
    };
    assert_eq!(validate_output_chunk(&data, 0).expect("data cursor"), 3);
    let eof = a3s_oci_sdk::OutputChunk {
        sequence: 4,
        stream: OutputStream::Stdout,
        data: Vec::new(),
        eof: true,
    };
    assert_eq!(validate_output_chunk(&eof, 3).expect("EOF cursor"), 4);

    let mut gap = data.clone();
    gap.sequence = 4;
    assert!(validate_output_chunk(&gap, 0).is_err());
    let mut empty_data = eof.clone();
    empty_data.eof = false;
    assert!(validate_output_chunk(&empty_data, 3).is_err());
    let mut eof_with_data = data;
    eof_with_data.eof = true;
    assert!(validate_output_chunk(&eof_with_data, 0).is_err());

    assert!(validate_output_stream_state(&eof, false, true, false).is_err());
    let mut stderr_after_eof = eof.clone();
    stderr_after_eof.stream = OutputStream::Stderr;
    assert!(validate_output_stream_state(&stderr_after_eof, false, false, true).is_err());
    assert!(validate_output_stream_state(&stderr_after_eof, true, false, false).is_err());
    assert!(validate_output_stream_state(&eof, false, false, false).is_ok());

    let error = validate_process_io_endpoints(&ProcessIoEndpoints {
        stdin: "",
        stdout: "stdout",
        stderr: "",
        terminal: false,
        await_start_activation: false,
        read_stdin_at_activation: false,
        stdin_sequence: 0,
        pending_stdin_write: None,
        stdin_close_state: StdinCloseState::Open,
        stdin_journal: None,
        output_cursor: 0,
        output_cursor_committer: None,
    })
    .expect_err("output without a durable cursor must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
}

#[test]
fn terminal_io_rejects_a_separate_stderr_fifo() {
    let error = validate_process_io_endpoints(&ProcessIoEndpoints {
        stdin: "stdin",
        stdout: "stdout",
        stderr: "stderr",
        terminal: true,
        await_start_activation: true,
        read_stdin_at_activation: true,
        stdin_sequence: 0,
        pending_stdin_write: None,
        stdin_close_state: StdinCloseState::Open,
        stdin_journal: None,
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

#[test]
fn stopped_stdin_startup_is_reported_without_panicking() {
    let error = stopped_stdin_startup_error();

    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(error.operation.as_deref(), Some("containerd-stdin"));
    assert!(error.message.contains("stopped startup state"));
}

mod output;
mod stdin;
