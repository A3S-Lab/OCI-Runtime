use super::io_operations::{init_process, io_fixture};
use super::*;

#[tokio::test]
async fn completed_process_io_mutations_replay_after_reopen_without_driver_dispatch() {
    let (temporary, driver, service, target) = io_fixture().await;
    let process = init_process(target);
    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("durable-write")),
        process: process.clone(),
        data: b"input".to_vec(),
    };
    let close = CloseStdinRequest {
        context: OperationContext::new(operation_id("durable-close")),
        process: process.clone(),
    };
    let resize = ResizeRequest {
        context: OperationContext::new(operation_id("durable-resize")),
        process,
        size: TerminalSize {
            width: 120,
            height: 40,
        },
    };

    service
        .write_stdin(write.clone())
        .await
        .expect("write stdin");
    service
        .close_stdin(close.clone())
        .await
        .expect("close stdin");
    service
        .resize(resize.clone())
        .await
        .expect("resize terminal");
    drop(service);

    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    reopened
        .write_stdin(write)
        .await
        .expect("replay stdin write after reopen");
    reopened
        .close_stdin(close)
        .await
        .expect("replay stdin close after reopen");
    reopened
        .resize(resize)
        .await
        .expect("replay terminal resize after reopen");

    assert_eq!(process_io_call_counts(&driver), (1, 1, 1));
}

#[tokio::test]
async fn process_io_operation_ids_reject_changed_payload_target_and_size() {
    let (_temporary, driver, service, target) = io_fixture().await;
    let process = init_process(target.clone());

    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("conflict-write")),
        process: process.clone(),
        data: b"first".to_vec(),
    };
    service
        .write_stdin(write.clone())
        .await
        .expect("initial stdin write");
    let mut changed_write = write;
    changed_write.data = b"changed".to_vec();
    assert_eq!(
        service
            .write_stdin(changed_write)
            .await
            .expect_err("changed stdin payload must conflict")
            .code,
        ErrorCode::FailedPrecondition
    );

    let close = CloseStdinRequest {
        context: OperationContext::new(operation_id("conflict-close")),
        process: process.clone(),
    };
    service
        .close_stdin(close.clone())
        .await
        .expect("initial stdin close");
    let mut changed_close = close;
    changed_close.process.process_id = ProcessId::new("different").expect("different process ID");
    assert_eq!(
        service
            .close_stdin(changed_close)
            .await
            .expect_err("changed stdin-close target must conflict")
            .code,
        ErrorCode::FailedPrecondition
    );

    let resize = ResizeRequest {
        context: OperationContext::new(operation_id("conflict-resize")),
        process,
        size: TerminalSize {
            width: 120,
            height: 40,
        },
    };
    service
        .resize(resize.clone())
        .await
        .expect("initial terminal resize");
    let mut changed_resize = resize;
    changed_resize.size.width = 121;
    assert_eq!(
        service
            .resize(changed_resize)
            .await
            .expect_err("changed terminal size must conflict")
            .code,
        ErrorCode::FailedPrecondition
    );

    assert_eq!(process_io_call_counts(&driver), (1, 1, 1));
}

#[tokio::test]
async fn terminal_process_io_failures_replay_after_reopen_and_release_claims() {
    let (temporary, driver, service, target) = io_fixture().await;
    let process = init_process(target);
    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("failed-write")),
        process: process.clone(),
        data: b"input".to_vec(),
    };
    let close = CloseStdinRequest {
        context: OperationContext::new(operation_id("failed-close")),
        process: process.clone(),
    };
    let resize = ResizeRequest {
        context: OperationContext::new(operation_id("failed-resize")),
        process,
        size: TerminalSize {
            width: 120,
            height: 40,
        },
    };
    let write_failure = Error::new(ErrorCode::Internal, "terminal stdin write failure")
        .for_operation("write-stdin");
    let close_failure = Error::new(ErrorCode::Internal, "terminal stdin close failure")
        .for_operation("close-stdin");
    let resize_failure =
        Error::new(ErrorCode::Internal, "terminal resize failure").for_operation("resize");

    driver.fail_next("write-stdin", write_failure.clone());
    assert_eq!(
        service
            .write_stdin(write.clone())
            .await
            .expect_err("stdin write must fail"),
        write_failure
    );
    driver.fail_next("close-stdin", close_failure.clone());
    assert_eq!(
        service
            .close_stdin(close.clone())
            .await
            .expect_err("stdin close must fail"),
        close_failure
    );
    driver.fail_next("resize", resize_failure.clone());
    assert_eq!(
        service
            .resize(resize.clone())
            .await
            .expect_err("terminal resize must fail"),
        resize_failure
    );
    drop(service);

    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    assert_eq!(
        reopened
            .write_stdin(write)
            .await
            .expect_err("failed stdin write must replay"),
        write_failure
    );
    assert_eq!(
        reopened
            .close_stdin(close)
            .await
            .expect_err("failed stdin close must replay"),
        close_failure
    );
    assert_eq!(
        reopened
            .resize(resize)
            .await
            .expect_err("failed terminal resize must replay"),
        resize_failure
    );

    assert_eq!(process_io_call_counts(&driver), (1, 1, 1));
}

#[tokio::test]
async fn exec_process_io_journals_release_and_replay_process_scoped_claims() {
    let (temporary, driver, service, target) = io_fixture().await;
    let mut pipe_exec = exec_request(target.clone(), "exec-io-create", "pipe-worker");
    pipe_exec.io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    let pipe_process = service
        .exec(pipe_exec)
        .await
        .expect("exec pipe process")
        .target;

    let failed_write = WriteStdinRequest {
        context: OperationContext::new(operation_id("exec-io-failed-write")),
        process: pipe_process.clone(),
        data: b"failed".to_vec(),
    };
    let write_failure = Error::new(ErrorCode::Internal, "terminal exec stdin write failure")
        .for_operation("write-stdin");
    driver.fail_next("write-stdin", write_failure.clone());
    assert_eq!(
        service
            .write_stdin(failed_write.clone())
            .await
            .expect_err("exec stdin write must fail"),
        write_failure
    );

    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("exec-io-write")),
        process: pipe_process.clone(),
        data: b"input".to_vec(),
    };
    service
        .write_stdin(write.clone())
        .await
        .expect("write exec stdin after released failure claim");
    let close = CloseStdinRequest {
        context: OperationContext::new(operation_id("exec-io-close")),
        process: pipe_process,
    };
    service
        .close_stdin(close.clone())
        .await
        .expect("close exec stdin");

    let mut terminal_exec = exec_request(target, "terminal-io-create", "terminal-worker");
    terminal_exec.process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh"],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .expect("valid terminal exec process");
    terminal_exec.io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: Some(TerminalSize {
            width: 80,
            height: 24,
        }),
    };
    let terminal_process = service
        .exec(terminal_exec)
        .await
        .expect("exec terminal process")
        .target;
    let resize = ResizeRequest {
        context: OperationContext::new(operation_id("exec-io-resize")),
        process: terminal_process,
        size: TerminalSize {
            width: 120,
            height: 40,
        },
    };
    service
        .resize(resize.clone())
        .await
        .expect("resize exec PTY");
    drop(service);

    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    assert_eq!(
        reopened
            .write_stdin(failed_write)
            .await
            .expect_err("failed exec stdin write must replay"),
        write_failure
    );
    reopened
        .write_stdin(write)
        .await
        .expect("replay successful exec stdin write");
    reopened
        .close_stdin(close)
        .await
        .expect("replay successful exec stdin close");
    reopened
        .resize(resize)
        .await
        .expect("replay successful exec PTY resize");

    assert_eq!(process_io_call_counts(&driver), (2, 1, 1));
}

fn process_io_call_counts(driver: &RecordingDriver) -> (usize, usize, usize) {
    let calls = driver.calls();
    (
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::WriteStdin(_)))
            .count(),
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::CloseStdin(_)))
            .count(),
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Resize(_)))
            .count(),
    )
}
