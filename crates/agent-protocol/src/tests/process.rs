use super::*;

#[tokio::test]
async fn protocol_v3_exec_signal_and_wait_are_exactly_process_scoped() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(20));
    let client = AgentClient::connect_for_test(host, token(20), 3, 3)
        .await
        .expect("connect protocol-v3 client");
    assert_eq!(client.hello().selected_version(), 3);
    assert_eq!(
        client.hello().capabilities().operations(),
        &[
            crate::AgentOperation::Create,
            crate::AgentOperation::State,
            crate::AgentOperation::Start,
            crate::AgentOperation::Kill,
            crate::AgentOperation::Delete,
            crate::AgentOperation::Wait,
            crate::AgentOperation::Exec,
            crate::AgentOperation::SignalProcess,
            crate::AgentOperation::WaitProcess,
        ]
    );

    let create = create_request_for("exec-container", 7, "exec-create");
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    client.create(create).await.expect("create exec container");
    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("exec-start")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("start exec container");

    let request = exec_request(target, "command-1", "exec-command-1");
    let process_target = request.target.clone();
    let process = client.exec(request).await.expect("exec process");
    assert_eq!(process.target(), &process_target);
    assert!(process.pid() > 0);
    assert!(!process.terminal());

    client
        .signal_process(AgentSignalProcessRequest {
            context: OperationContext::new(operation_id("signal-command-1")),
            target: process_target.clone(),
            signal: Signal::new(15).expect("signal"),
        })
        .await
        .expect("signal exec process");
    let wait = AgentWaitProcessRequest {
        target: process_target,
        timeout_ms: Some(1_000),
    };
    let expected = ExitStatus::signaled(15, false).expect("exit status");
    assert_eq!(
        client
            .wait_process(wait.clone())
            .await
            .expect("first process wait"),
        expected
    );
    assert_eq!(
        client
            .wait_process(wait)
            .await
            .expect("repeated process wait"),
        expected
    );

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v3 server shutdown");
}

#[tokio::test]
async fn protocol_v4_freezes_and_lists_one_exact_container_generation() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(23));
    let client = AgentClient::connect_for_test(host, token(23), 4, 4)
        .await
        .expect("connect protocol-v4 client");
    assert_eq!(client.hello().selected_version(), 4);
    assert_eq!(
        &client.hello().capabilities().operations()[9..],
        &[
            crate::AgentOperation::Pause,
            crate::AgentOperation::Resume,
            crate::AgentOperation::Processes,
        ]
    );

    let create = create_request_for("control-container", 4, "control-create");
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    client
        .create(create)
        .await
        .expect("create control container");
    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("control-start")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("start control container");
    let resources = serde_json::from_value(serde_json::json!({
        "memory": {"limit": 4096}
    }))
    .expect("decode resource update");
    let error = client
        .update(AgentUpdateRequest {
            context: OperationContext::new(operation_id("v4-update")),
            target: target.clone(),
            resources,
        })
        .await
        .expect_err("protocol-v4 client must reject a v5 update locally");
    assert_eq!(error.code, ErrorCode::Unsupported);

    let initial = client
        .processes(AgentProcessesRequest {
            target: target.clone(),
        })
        .await
        .expect("list init process");
    assert_eq!(initial.len(), 1);
    assert!(initial[0].target.process_id.is_init());

    let exec = exec_request(target.clone(), "listed-command", "control-exec");
    let exec_target = exec.target.clone();
    client.exec(exec).await.expect("exec listed process");
    let processes = client
        .processes(AgentProcessesRequest {
            target: target.clone(),
        })
        .await
        .expect("list init and exec processes");
    assert_eq!(processes.len(), 2);
    assert!(processes
        .iter()
        .any(|process| process.target == exec_target));

    let paused = client
        .pause(AgentContainerOperationRequest {
            context: OperationContext::new(operation_id("control-pause")),
            target: target.clone(),
        })
        .await
        .expect("pause container");
    assert!(paused.paused());
    assert!(client
        .state(AgentStateRequest {
            target: target.clone(),
        })
        .await
        .expect("state paused container")
        .paused());
    let rejected = client
        .exec(exec_request(
            target.clone(),
            "paused-command",
            "control-paused-exec",
        ))
        .await
        .expect_err("exec while paused must fail");
    assert_eq!(rejected.code, ErrorCode::FailedPrecondition);

    let resumed = client
        .resume(AgentContainerOperationRequest {
            context: OperationContext::new(operation_id("control-resume")),
            target,
        })
        .await
        .expect("resume container");
    assert!(!resumed.paused());

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v4 server shutdown");
}

#[tokio::test]
async fn protocol_v5_updates_resources_and_returns_typed_stats() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(24));
    let client = AgentClient::connect_for_test(host, token(24), 5, 5)
        .await
        .expect("connect protocol-v5 client");
    assert_eq!(client.hello().selected_version(), 5);
    assert_eq!(
        &client.hello().capabilities().operations()[12..],
        &[crate::AgentOperation::Update, crate::AgentOperation::Stats,]
    );

    let create = create_request_for("resource-container", 8, "resource-create");
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    client
        .create(create)
        .await
        .expect("create resource container");
    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("resource-start")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("start resource container");

    let resources = serde_json::from_value(serde_json::json!({
        "memory": {"limit": 4096},
        "cpu": {"shares": 1024},
        "pids": {"limit": 16}
    }))
    .expect("decode resource update");
    let updated = client
        .update(AgentUpdateRequest {
            context: OperationContext::new(operation_id("resource-update")),
            target: target.clone(),
            resources,
        })
        .await
        .expect("update resources");
    assert_eq!(updated.target(), &target);
    assert_eq!(updated.status(), ContainerState::Running);

    let stats = client
        .stats(AgentStatsRequest {
            target: target.clone(),
        })
        .await
        .expect("read resource stats");
    assert_eq!(stats.target, target);
    assert_eq!(stats.cpu.usage_ns, 30);
    assert_eq!(stats.memory.limit_bytes, Some(4_096));
    assert_eq!(stats.process_count, 1);
    assert_eq!(stats.metrics["memory.events.oom_kill"], 0);

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v5 server shutdown");
}

#[tokio::test]
async fn protocol_v6_captures_output_and_controls_stdin() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let agent = Arc::new(TestAgent::default());
    let server = spawn_server_with_agent(guest, token(25), Arc::clone(&agent));
    let client = AgentClient::connect_for_test(host, token(25), 6, 6)
        .await
        .expect("connect protocol-v6 client");
    assert_eq!(client.hello().selected_version(), 6);
    assert_eq!(
        &client.hello().capabilities().operations()[14..],
        &[
            crate::AgentOperation::ReadOutput,
            crate::AgentOperation::WriteStdin,
            crate::AgentOperation::CloseStdin,
        ]
    );

    let mut create = create_request_for("io-container", 9, "io-create");
    create.io.stdin = IoMode::Pipe;
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    client.create(create).await.expect("create I/O container");
    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("io-start")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("start I/O container");
    let process = ProcessTarget {
        container: target.clone(),
        process_id: ProcessId::init(),
    };

    client
        .write_stdin(AgentWriteStdinRequest {
            context: None,
            process: process.clone(),
            data: b"input".to_vec(),
        })
        .await
        .expect("write stdin");
    let first = client
        .read_output(AgentReadOutputRequest {
            process: process.clone(),
            after_sequence: 0,
            max_bytes: 3,
            wait_timeout_ms: None,
        })
        .await
        .expect("first output poll");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].sequence, 3);
    assert_eq!(first[0].data, b"rea");

    let second = client
        .read_output(AgentReadOutputRequest {
            process: process.clone(),
            after_sequence: first[0].sequence,
            max_bytes: 3,
            wait_timeout_ms: Some(100),
        })
        .await
        .expect("second output poll");
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].data, b"dy\n");
    assert!(second[1].eof);

    client
        .close_stdin(AgentCloseStdinRequest {
            context: None,
            process: process.clone(),
        })
        .await
        .expect("close stdin");
    client
        .close_stdin(AgentCloseStdinRequest {
            context: None,
            process: process.clone(),
        })
        .await
        .expect("repeat stdin close");
    let error = client
        .write_stdin(AgentWriteStdinRequest {
            context: None,
            process: process.clone(),
            data: b"late".to_vec(),
        })
        .await
        .expect_err("write after close must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    let resize_error = client
        .resize(AgentResizeRequest {
            context: None,
            process: process.clone(),
            size: TerminalSize {
                width: 120,
                height: 40,
            },
        })
        .await
        .expect_err("protocol-v6 client must reject a v7 terminal resize locally");
    assert_eq!(resize_error.code, ErrorCode::Unsupported);

    let generation = target.generation.expect("exact target");
    let key = (target.id, generation, ProcessId::init());
    {
        let state = agent.state.lock().expect("agent state lock");
        assert_eq!(state.stdin[&key], b"input");
        assert!(state.stdin_closed.contains(&key));
    }

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v6 server shutdown");
}

#[tokio::test]
async fn protocol_v7_resizes_one_exact_process_terminal() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let agent = Arc::new(TestAgent::default());
    let server = spawn_server_with_agent(guest, token(27), Arc::clone(&agent));
    let client = AgentClient::connect_for_test(host, token(27), 7, 7)
        .await
        .expect("connect protocol-v7 client");
    assert_eq!(client.hello().selected_version(), 7);
    assert_eq!(
        client.hello().capabilities().operations().last(),
        Some(&crate::AgentOperation::Resize)
    );

    let create = create_request_for("terminal-container", 10, "terminal-create");
    let target = create.target.clone();
    client
        .create(create)
        .await
        .expect("create terminal container");
    let process = ProcessTarget {
        container: target,
        process_id: ProcessId::init(),
    };
    let size = TerminalSize {
        width: 120,
        height: 40,
    };
    client
        .resize(AgentResizeRequest {
            context: None,
            process: process.clone(),
            size,
        })
        .await
        .expect("resize terminal");
    let context_error = client
        .resize(AgentResizeRequest {
            context: Some(OperationContext::new(operation_id("v7-resize-context"))),
            process: process.clone(),
            size,
        })
        .await
        .expect_err("protocol-v7 client must reject v8 mutation context");
    assert_eq!(context_error.code, ErrorCode::Unsupported);

    let key = process_key(&process).expect("exact process key");
    assert_eq!(
        agent.state.lock().expect("agent state lock").terminal_sizes[&key],
        size
    );

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v7 server shutdown");
}

#[tokio::test]
async fn protocol_v8_requires_durable_context_for_process_io_mutations() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let agent = Arc::new(TestAgent::default());
    let server = spawn_server_with_agent(guest, token(29), Arc::clone(&agent));
    let client = AgentClient::connect(host, token(29))
        .await
        .expect("connect protocol-v8 client");
    assert_eq!(client.hello().selected_version(), 8);

    let mut create = create_request_for("durable-io-container", 11, "durable-io-create");
    create.io.stdin = IoMode::Pipe;
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    client
        .create(create)
        .await
        .expect("create durable I/O container");
    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("durable-io-start")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("start durable I/O container");
    let process = ProcessTarget {
        container: target.clone(),
        process_id: ProcessId::init(),
    };
    let size = TerminalSize {
        width: 120,
        height: 40,
    };

    let write_error = client
        .write_stdin(AgentWriteStdinRequest {
            context: None,
            process: process.clone(),
            data: b"missing-context".to_vec(),
        })
        .await
        .expect_err("protocol-v8 stdin write without context must fail");
    assert_eq!(write_error.code, ErrorCode::InvalidArgument);
    let close_error = client
        .close_stdin(AgentCloseStdinRequest {
            context: None,
            process: process.clone(),
        })
        .await
        .expect_err("protocol-v8 stdin close without context must fail");
    assert_eq!(close_error.code, ErrorCode::InvalidArgument);
    let resize_error = client
        .resize(AgentResizeRequest {
            context: None,
            process: process.clone(),
            size,
        })
        .await
        .expect_err("protocol-v8 terminal resize without context must fail");
    assert_eq!(resize_error.code, ErrorCode::InvalidArgument);

    client
        .write_stdin(AgentWriteStdinRequest {
            context: Some(OperationContext::new(operation_id("durable-io-write"))),
            process: process.clone(),
            data: b"input".to_vec(),
        })
        .await
        .expect("write stdin with durable context");
    client
        .resize(AgentResizeRequest {
            context: Some(OperationContext::new(operation_id("durable-io-resize"))),
            process: process.clone(),
            size,
        })
        .await
        .expect("resize terminal with durable context");
    client
        .close_stdin(AgentCloseStdinRequest {
            context: Some(OperationContext::new(operation_id("durable-io-close"))),
            process: process.clone(),
        })
        .await
        .expect("close stdin with durable context");

    let generation = target.generation.expect("exact target");
    let key = (target.id, generation, ProcessId::init());
    {
        let state = agent.state.lock().expect("agent state lock");
        assert_eq!(state.stdin[&key], b"input");
        assert_eq!(state.terminal_sizes[&key], size);
        assert!(state.stdin_closed.contains(&key));
    }

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v8 server shutdown");
}

#[tokio::test]
async fn protocol_v6_filters_and_rejects_forged_v7_terminal_resize() {
    let (mut host, guest) = tokio::io::duplex(1024 * 1024);
    let expected_token = token(28);
    let server = spawn_server(guest, expected_token.clone());

    write_frame(
        &mut host,
        &HostHello {
            protocols: ProtocolRange { min: 6, max: 6 },
            token: expected_token,
        },
    )
    .await
    .expect("write protocol-v6 hello");
    let hello: HelloOutcome = read_frame(&mut host)
        .await
        .expect("read protocol-v6 hello")
        .expect("server returned protocol-v6 hello");
    let HelloOutcome::Accepted { hello } = hello else {
        panic!("protocol-v6 negotiation was rejected");
    };
    assert_eq!(hello.selected_version(), 6);
    assert!(!hello
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::Resize));

    write_frame(
        &mut host,
        &RequestEnvelope {
            version: 6,
            request_id: 43,
            request: AgentRequest::Resize(AgentResizeRequest {
                context: None,
                process: ProcessTarget {
                    container: ContainerTarget::exact(
                        container_id("forged-terminal"),
                        Generation(1),
                    ),
                    process_id: ProcessId::init(),
                },
                size: TerminalSize {
                    width: 120,
                    height: 40,
                },
            }),
        },
    )
    .await
    .expect("write forged protocol-v6 terminal resize");
    let response: ResponseEnvelope = read_frame(&mut host)
        .await
        .expect("read forged terminal resize response")
        .expect("server returned forged terminal resize response");
    assert_eq!(response.version, 6);
    assert_eq!(response.request_id, 43);
    let ResponseOutcome::Failed { error } = response.outcome else {
        panic!("forged protocol-v6 terminal resize unexpectedly succeeded");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);

    drop(host);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v6 server shutdown");
}

#[tokio::test]
async fn protocol_v5_filters_and_rejects_forged_v6_process_io() {
    let (mut host, guest) = tokio::io::duplex(1024 * 1024);
    let expected_token = token(26);
    let server = spawn_server(guest, expected_token.clone());

    write_frame(
        &mut host,
        &HostHello {
            protocols: ProtocolRange { min: 5, max: 5 },
            token: expected_token,
        },
    )
    .await
    .expect("write protocol-v5 hello");
    let hello: HelloOutcome = read_frame(&mut host)
        .await
        .expect("read protocol-v5 hello")
        .expect("server returned protocol-v5 hello");
    let HelloOutcome::Accepted { hello } = hello else {
        panic!("protocol-v5 negotiation was rejected");
    };
    assert_eq!(hello.selected_version(), 5);
    for operation in [
        crate::AgentOperation::ReadOutput,
        crate::AgentOperation::WriteStdin,
        crate::AgentOperation::CloseStdin,
    ] {
        assert!(!hello.capabilities().operations().contains(&operation));
    }

    write_frame(
        &mut host,
        &RequestEnvelope {
            version: 5,
            request_id: 42,
            request: AgentRequest::ReadOutput(AgentReadOutputRequest {
                process: ProcessTarget {
                    container: ContainerTarget::exact(container_id("forged-io"), Generation(1)),
                    process_id: ProcessId::init(),
                },
                after_sequence: 0,
                max_bytes: 1,
                wait_timeout_ms: None,
            }),
        },
    )
    .await
    .expect("write forged protocol-v5 process-I/O request");
    let response: ResponseEnvelope = read_frame(&mut host)
        .await
        .expect("read forged process-I/O response")
        .expect("server returned forged process-I/O response");
    assert_eq!(response.version, 5);
    assert_eq!(response.request_id, 42);
    let ResponseOutcome::Failed { error } = response.outcome else {
        panic!("forged protocol-v5 process-I/O request unexpectedly succeeded");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);

    drop(host);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v5 server shutdown");
}

#[tokio::test]
async fn protocol_v2_filters_and_rejects_forged_v3_process_operations() {
    let (mut host, guest) = tokio::io::duplex(1024 * 1024);
    let agent = Arc::new(TestAgent::default());
    let expected_token = token(21);
    let server = spawn_server_with_agent(guest, expected_token.clone(), agent.clone());

    write_frame(
        &mut host,
        &HostHello {
            protocols: ProtocolRange { min: 2, max: 2 },
            token: expected_token,
        },
    )
    .await
    .expect("write protocol-v2 hello");
    let hello: HelloOutcome = read_frame(&mut host)
        .await
        .expect("read protocol-v2 hello")
        .expect("server returned protocol-v2 hello");
    let HelloOutcome::Accepted { hello } = hello else {
        panic!("protocol-v2 negotiation was rejected");
    };
    assert_eq!(hello.selected_version(), 2);
    assert!(!hello
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::Exec));
    assert!(!hello
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::SignalProcess));
    assert!(!hello
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::WaitProcess));

    let mut forged = exec_request(
        ContainerTarget::exact(container_id("forged-exec"), Generation(1)),
        "forged-command",
        "forged-exec-operation",
    );
    forged.process = serde_json::from_str(
        r#"{
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": [],
            "cwd": "/"
        }"#,
    )
    .expect("structurally valid but semantically invalid OCI process");
    write_frame(
        &mut host,
        &RequestEnvelope {
            version: 2,
            request_id: 42,
            request: AgentRequest::Exec(Box::new(forged)),
        },
    )
    .await
    .expect("write forged protocol-v2 exec");
    let response: ResponseEnvelope = read_frame(&mut host)
        .await
        .expect("read forged exec response")
        .expect("server returned forged exec response");
    assert_eq!(response.version, 2);
    assert_eq!(response.request_id, 42);
    let ResponseOutcome::Failed { error } = response.outcome else {
        panic!("forged protocol-v2 exec unexpectedly succeeded");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(agent.exec_dispatches.load(Ordering::SeqCst), 0);

    drop(host);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v2 server shutdown");
}

#[tokio::test]
async fn mismatched_exec_process_response_permanently_poisons_the_connection() {
    let (host, mut guest) = tokio::io::duplex(1024 * 1024);
    let malicious = tokio::spawn(async move {
        let _: HostHello = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing hello"))?;
        let capabilities = AgentCapabilities::new(
            "malicious-test",
            std::env::consts::ARCH,
            vec![crate::AgentOperation::Exec],
        )?;
        write_frame(
            &mut guest,
            &HelloOutcome::Accepted {
                hello: AgentHello::new(3, capabilities),
            },
        )
        .await?;
        let request: RequestEnvelope = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing request"))?;
        let AgentRequest::Exec(exec) = request.request else {
            return Err(Error::new(ErrorCode::Internal, "expected exec"));
        };
        let wrong = AgentProcess::new(
            ProcessTarget {
                container: exec.target.container,
                process_id: process_id("different-command"),
            },
            303,
            false,
        )?;
        write_frame(
            &mut guest,
            &ResponseEnvelope {
                version: 3,
                request_id: request.request_id,
                outcome: ResponseOutcome::Succeeded {
                    response: AgentResponse::Process(wrong),
                },
            },
        )
        .await?;
        Ok::<_, Error>(())
    });

    let client = AgentClient::connect(host, token(22))
        .await
        .expect("connect malicious protocol-v3 peer");
    let request = exec_request(
        ContainerTarget::exact(container_id("correlation-container"), Generation(1)),
        "expected-command",
        "correlation-exec",
    );
    let error = client
        .exec(request.clone())
        .await
        .expect_err("mismatched process target must fail");
    assert_eq!(error.code, ErrorCode::Conflict);
    let error = client
        .exec(request)
        .await
        .expect_err("connection must stay poisoned");
    assert_eq!(error.code, ErrorCode::Unavailable);
    malicious
        .await
        .expect("malicious task")
        .expect("malicious response written");
}
