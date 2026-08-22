use super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

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

    let fifo =
        open_fifo(path.to_str().expect("UTF-8 path"), true, false).expect("open nonblocking FIFO");
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
async fn stdin_pump_replays_pending_write_and_continues_after_durable_sequence() {
    use std::os::unix::ffi::OsStrExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("journaled-stdin");
    let path_c =
        std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path without NUL");
    let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "create test FIFO: {}",
        io::Error::last_os_error()
    );

    let pending_data = b"pending\n".to_vec();
    let fresh_data = b"fresh\n".to_vec();
    let pending_operation =
        crate::identity::operation("k8s.io", "journaled-stdin", None, None, "write-stdin-5")
            .expect("pending stdin operation")
            .operation_id;
    let fresh_operation =
        crate::identity::operation("k8s.io", "journaled-stdin", None, None, "write-stdin-6")
            .expect("fresh stdin operation")
            .operation_id;
    let service =
        ReplaySafeStdinService::with_completed(pending_operation.clone(), pending_data.clone());
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(service.clone()),
        a3s_oci_sdk::IsolationRequest::SharedHostKernel,
    );
    let journal = Arc::new(RecordingStdinJournal::default());
    let identity = TaskIdentity::new("k8s.io", "journaled-stdin").expect("task identity");
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
            read_stdin_at_activation: false,
            stdin_sequence: 4,
            pending_stdin_write: Some(
                PendingStdinWrite::new(5, pending_data.clone()).expect("pending stdin write"),
            ),
            stdin_close_state: StdinCloseState::Open,
            stdin_journal: Some(journal.clone()),
            output_cursor: 0,
            output_cursor_committer: None,
        },
    )
    .expect("start journaled stdin pump");
    let writer = open_fifo(path.to_str().expect("UTF-8 FIFO path"), false, true)
        .expect("open journaled stdin writer");
    let cancellation = PumpCancellation::new();
    let mut receiver = cancellation.subscribe();
    write_all(&writer, &fresh_data, &mut receiver)
        .await
        .expect("write fresh stdin");

    pumps
        .stdin_drain()
        .expect("stdin drain")
        .request_and_wait()
        .await
        .expect("replay and drain journaled stdin");

    assert_eq!(
        *service.requests.lock().expect("stdin requests"),
        vec![pending_operation, fresh_operation]
    );
    assert_eq!(
        *service.effects.lock().expect("stdin effects"),
        vec![pending_data, fresh_data.clone()],
        "replaying the pending operation must not duplicate its remote effect"
    );
    assert_eq!(
        *journal.prepared.lock().expect("prepared stdin journal"),
        vec![(6, fresh_data)]
    );
    assert_eq!(
        *journal.committed.lock().expect("committed stdin journal"),
        vec![5, 6]
    );
    assert!(pumps.failure().is_none());
    pumps.stop().await;
}

#[tokio::test]
async fn stdin_pump_finishes_a_durable_close_without_reopening_its_fifo() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let missing_fifo = directory.path().join("already-closed-stdin");
    let service = BlockingStdinService::default();
    service.mark_producer_finished();
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(service.clone()),
        a3s_oci_sdk::IsolationRequest::SharedHostKernel,
    );
    let journal = Arc::new(RecordingStdinJournal::default());
    let identity = TaskIdentity::new("k8s.io", "closing-stdin").expect("task identity");
    let mut pumps = start_process_pumps(
        adapter,
        identity,
        Generation(7),
        None,
        ProcessIoEndpoints {
            stdin: missing_fifo.to_str().expect("UTF-8 FIFO path"),
            stdout: "",
            stderr: "",
            terminal: false,
            await_start_activation: false,
            read_stdin_at_activation: false,
            stdin_sequence: 3,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Closing,
            stdin_journal: Some(journal.clone()),
            output_cursor: 0,
            output_cursor_committer: None,
        },
    )
    .expect("restore closing stdin pump without a FIFO");
    let mut drain = pumps.stdin_drain().expect("closing stdin drain");
    tokio::time::timeout(Duration::from_secs(1), drain.wait_for_completion())
        .await
        .expect("closing stdin replay deadline")
        .expect("closing stdin replay");
    assert_eq!(
        service.captured.lock().expect("captured stdin").close_calls,
        1
    );
    assert_eq!(
        journal
            .close_prepares
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        journal
            .close_commits
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(pumps.failure().is_none());
    pumps.stop().await;

    let closed_service = BlockingStdinService::default();
    let closed_adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(closed_service.clone()),
        a3s_oci_sdk::IsolationRequest::SharedHostKernel,
    );
    let closed_journal = Arc::new(RecordingStdinJournal::default());
    let closed_identity = TaskIdentity::new("k8s.io", "closed-stdin").expect("task identity");
    let mut closed_pumps = start_process_pumps(
        closed_adapter,
        closed_identity,
        Generation(7),
        None,
        ProcessIoEndpoints {
            stdin: missing_fifo.to_str().expect("UTF-8 FIFO path"),
            stdout: "",
            stderr: "",
            terminal: false,
            await_start_activation: false,
            read_stdin_at_activation: false,
            stdin_sequence: 3,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Closed,
            stdin_journal: Some(closed_journal.clone()),
            output_cursor: 0,
            output_cursor_committer: None,
        },
    )
    .expect("restore closed stdin pump without a FIFO");
    let mut closed_drain = closed_pumps.stdin_drain().expect("closed stdin drain");
    tokio::time::timeout(Duration::from_secs(1), closed_drain.wait_for_completion())
        .await
        .expect("closed stdin completion deadline")
        .expect("closed stdin completion");
    assert_eq!(
        closed_service
            .captured
            .lock()
            .expect("captured stdin")
            .close_calls,
        0
    );
    assert_eq!(
        closed_journal
            .close_commits
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(closed_pumps.failure().is_none());
    closed_pumps.stop().await;
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
            read_stdin_at_activation: true,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            stdin_journal: None,
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
            read_stdin_at_activation: true,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            stdin_journal: None,
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
            read_stdin_at_activation: false,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            stdin_journal: None,
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
            read_stdin_at_activation: true,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            stdin_journal: None,
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
