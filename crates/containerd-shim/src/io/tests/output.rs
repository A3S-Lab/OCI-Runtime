use super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

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
            read_stdin_at_activation: false,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            stdin_journal: None,
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
async fn output_cancellation_commits_only_the_fifo_delivered_prefix() {
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
    let filler_writer = open_fifo(path.to_str().expect("UTF-8 FIFO path"), false, true)
        .expect("open output filler writer");
    let filler_block = [0xa5_u8; 4 * 1024];
    let mut filler_bytes = 0_usize;
    loop {
        match filler_writer.get_ref().write(&filler_block) {
            Ok(0) => panic!("output filler FIFO accepted zero bytes"),
            Ok(written) => filler_bytes += written,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill output FIFO: {error}"),
        }
    }
    assert!(filler_bytes > 0, "output FIFO accepted no filler bytes");
    let mut drained_filler = vec![0_u8; filler_block.len().min(filler_bytes)];
    let drained = reader
        .get_ref()
        .read(&mut drained_filler)
        .expect("make bounded room in output FIFO");
    assert!(drained > 0, "output FIFO released no filler bytes");
    assert!(drained_filler[..drained].iter().all(|byte| *byte == 0xa5));
    let retained_filler = filler_bytes - drained;

    let payload = (0..usize::try_from(OUTPUT_READ_BYTES).expect("output read bound"))
        .map(|index| u8::try_from(index % 251).expect("bounded output byte"))
        .collect::<Vec<_>>();
    let runtime = OutputReplayService::with_payload(payload.clone());
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(runtime),
        a3s_oci_sdk::IsolationRequest::SharedHostKernel,
    );
    let committer = Arc::new(GatedCursorCommitter::new());
    let identity = TaskIdentity::new("k8s.io", "cancelled-output").expect("task identity");
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
            read_stdin_at_activation: false,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            stdin_journal: None,
            output_cursor: 0,
            output_cursor_committer: Some(committer.clone()),
        },
    )
    .expect("start cancellable output pump");

    tokio::time::timeout(Duration::from_secs(1), committer.wait_for_commits(1))
        .await
        .expect("partial output cursor commit deadline");
    let cursor = committer.cursors.lock().expect("committed cursors")[0];
    let delivered = usize::try_from(cursor).expect("delivered output cursor");
    assert!(delivered > 0, "cancellation lost the delivered FIFO prefix");
    assert!(
        delivered < payload.len(),
        "cancellation committed the unwritten output suffix"
    );

    pumps.cancellation.cancel();
    committer.release_commit();
    tokio::time::timeout(Duration::from_secs(1), pumps.stop())
        .await
        .expect("cancelled output pump stop deadline");
    let expected = retained_filler + delivered;
    let mut actual = Vec::with_capacity(expected);
    while actual.len() < expected {
        let mut guard = tokio::time::timeout(Duration::from_secs(1), reader.readable())
            .await
            .expect("delivered output readable deadline")
            .expect("delivered output readable");
        let mut bytes = vec![0_u8; (expected - actual.len()).min(FIFO_BUFFER_BYTES)];
        match guard.try_io(|handle| handle.get_ref().read(&mut bytes)) {
            Ok(Ok(0)) => panic!("output FIFO reached EOF before the committed cursor"),
            Ok(Ok(length)) => actual.extend_from_slice(&bytes[..length]),
            Ok(Err(error)) => panic!("read delivered output prefix: {error}"),
            Err(_) => continue,
        }
    }
    assert!(actual[..retained_filler].iter().all(|byte| *byte == 0xa5));
    assert_eq!(actual[retained_filler..], payload[..delivered]);
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
    let handle =
        open_fifo(path.to_str().expect("UTF-8 path"), true, false).expect("open nonblocking FIFO");
    assert!(handle.get_ref().as_raw_fd() >= 0);
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
