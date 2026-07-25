use super::*;

async fn io_fixture() -> (
    tempfile::TempDir,
    Arc<RecordingDriver>,
    HostRuntimeService,
    ContainerTarget,
) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_control_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let mut create = create_request(&bundle_directory, "io-create");
    create.io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id, created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("io-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    (temporary, driver, service, target)
}

fn init_process(container: ContainerTarget) -> ProcessTarget {
    ProcessTarget {
        container,
        process_id: ProcessId::init(),
    }
}

#[tokio::test]
async fn process_io_resolves_current_targets_to_the_exact_generation() {
    let (_temporary, driver, service, target) = io_fixture().await;
    let current = init_process(ContainerTarget::current(target.id.clone()));

    let chunks = service
        .read_output(ReadOutputRequest {
            process: current.clone(),
            after_sequence: 0,
            max_bytes: 64,
            wait_timeout_ms: Some(25),
        })
        .await
        .expect("read output");
    assert_eq!(
        chunks,
        vec![OutputChunk {
            sequence: 1,
            stream: OutputStream::Stdout,
            data: Vec::new(),
            eof: true,
        }]
    );
    service
        .write_stdin(WriteStdinRequest {
            process: current.clone(),
            data: b"input".to_vec(),
        })
        .await
        .expect("write stdin");
    service
        .close_stdin(CloseStdinRequest {
            process: current.clone(),
        })
        .await
        .expect("close stdin");
    service
        .close_stdin(CloseStdinRequest { process: current })
        .await
        .expect("repeat close stdin");
    service
        .resize(ResizeRequest {
            process: init_process(ContainerTarget::current(target.id.clone())),
            size: TerminalSize {
                width: 120,
                height: 40,
            },
        })
        .await
        .expect("resize terminal");

    let exact = init_process(target);
    let io_calls = driver
        .calls()
        .into_iter()
        .filter(|call| {
            matches!(
                call,
                DriverCall::ReadOutput(_)
                    | DriverCall::WriteStdin(_)
                    | DriverCall::CloseStdin(_)
                    | DriverCall::Resize(_)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        io_calls,
        vec![
            DriverCall::ReadOutput(DriverReadOutputRequest {
                target: exact.clone(),
                after_sequence: 0,
                max_bytes: 64,
                wait_timeout_ms: Some(25),
            }),
            DriverCall::WriteStdin(DriverWriteStdinRequest {
                target: exact.clone(),
                data: b"input".to_vec(),
            }),
            DriverCall::CloseStdin(exact.clone()),
            DriverCall::CloseStdin(exact.clone()),
            DriverCall::Resize(DriverResizeRequest {
                target: exact,
                size: TerminalSize {
                    width: 120,
                    height: 40,
                },
            }),
        ]
    );
}

#[tokio::test]
async fn process_io_rejects_generation_mismatches_and_missing_processes_before_dispatch() {
    let (_temporary, driver, service, target) = io_fixture().await;
    let wrong_generation = Generation(target.generation.expect("exact generation").0 + 1);
    let mismatched = init_process(ContainerTarget::exact(target.id.clone(), wrong_generation));

    let read_error = service
        .read_output(ReadOutputRequest {
            process: mismatched.clone(),
            after_sequence: 0,
            max_bytes: 1,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("generation-mismatched output read must fail");
    assert_eq!(read_error.code, ErrorCode::Conflict);
    let write_error = service
        .write_stdin(WriteStdinRequest {
            process: mismatched.clone(),
            data: b"x".to_vec(),
        })
        .await
        .expect_err("generation-mismatched stdin write must fail");
    assert_eq!(write_error.code, ErrorCode::Conflict);
    let close_error = service
        .close_stdin(CloseStdinRequest {
            process: mismatched,
        })
        .await
        .expect_err("generation-mismatched stdin close must fail");
    assert_eq!(close_error.code, ErrorCode::Conflict);
    let resize_error = service
        .resize(ResizeRequest {
            process: init_process(ContainerTarget::exact(target.id.clone(), wrong_generation)),
            size: TerminalSize {
                width: 120,
                height: 40,
            },
        })
        .await
        .expect_err("generation-mismatched terminal resize must fail");
    assert_eq!(resize_error.code, ErrorCode::Conflict);

    let missing = ProcessTarget {
        container: ContainerTarget::current(target.id),
        process_id: ProcessId::new("missing").expect("process ID"),
    };
    let missing_error = service
        .read_output(ReadOutputRequest {
            process: missing,
            after_sequence: 0,
            max_bytes: 1,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("missing process output read must fail");
    assert_eq!(missing_error.code, ErrorCode::NotFound);
    assert!(!driver.calls().iter().any(|call| {
        matches!(
            call,
            DriverCall::ReadOutput(_)
                | DriverCall::WriteStdin(_)
                | DriverCall::CloseStdin(_)
                | DriverCall::Resize(_)
        )
    }));
}

#[tokio::test]
async fn process_output_rejects_malformed_driver_chunks_and_byte_overruns() {
    let (_temporary, driver, service, target) = io_fixture().await;
    let process = init_process(target);

    driver.queue_output(vec![OutputChunk {
        sequence: 2,
        stream: OutputStream::Stdout,
        data: b"x".to_vec(),
        eof: false,
    }]);
    let cursor_error = service
        .read_output(ReadOutputRequest {
            process: process.clone(),
            after_sequence: 0,
            max_bytes: 8,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("non-contiguous output cursor must fail");
    assert_eq!(cursor_error.code, ErrorCode::Conflict);

    driver.queue_output(vec![OutputChunk {
        sequence: 1,
        stream: OutputStream::Stdout,
        data: Vec::new(),
        eof: false,
    }]);
    let empty_error = service
        .read_output(ReadOutputRequest {
            process: process.clone(),
            after_sequence: 0,
            max_bytes: 8,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("empty data chunk must fail");
    assert_eq!(empty_error.code, ErrorCode::Conflict);

    driver.queue_output(vec![OutputChunk {
        sequence: 1,
        stream: OutputStream::Stderr,
        data: b"x".to_vec(),
        eof: true,
    }]);
    let eof_error = service
        .read_output(ReadOutputRequest {
            process: process.clone(),
            after_sequence: 0,
            max_bytes: 8,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("EOF data must fail");
    assert_eq!(eof_error.code, ErrorCode::Internal);

    driver.queue_output(vec![OutputChunk {
        sequence: 2,
        stream: OutputStream::Stdout,
        data: b"xy".to_vec(),
        eof: false,
    }]);
    let limit_error = service
        .read_output(ReadOutputRequest {
            process,
            after_sequence: 0,
            max_bytes: 1,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("driver byte overrun must fail");
    assert_eq!(limit_error.code, ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn process_io_request_limits_fail_before_driver_dispatch() {
    let (_temporary, driver, service, target) = io_fixture().await;
    let process = init_process(target);

    let read_error = service
        .read_output(ReadOutputRequest {
            process: process.clone(),
            after_sequence: 0,
            max_bytes: a3s_oci_sdk::MAX_OUTPUT_READ_BYTES + 1,
            wait_timeout_ms: None,
        })
        .await
        .expect_err("oversized output poll must fail");
    assert_eq!(read_error.code, ErrorCode::InvalidArgument);

    let write_error = service
        .write_stdin(WriteStdinRequest {
            process,
            data: vec![0; a3s_oci_sdk::MAX_STDIN_WRITE_BYTES + 1],
        })
        .await
        .expect_err("oversized stdin write must fail");
    assert_eq!(write_error.code, ErrorCode::InvalidArgument);
    assert!(!driver
        .calls()
        .iter()
        .any(|call| { matches!(call, DriverCall::ReadOutput(_) | DriverCall::WriteStdin(_)) }));
}
