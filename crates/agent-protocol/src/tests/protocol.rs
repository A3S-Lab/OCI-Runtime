use super::*;

#[tokio::test]
async fn negotiates_and_round_trips_the_core_oci_lifecycle() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(7));
    let client = AgentClient::connect_for_test(host, token(7), 1, 1)
        .await
        .expect("connect agent client");
    assert_eq!(client.hello().selected_version(), 1);
    assert_eq!(client.hello().capabilities().operations().len(), 5);

    let create = create_request();
    let digest = create.bundle.config_digest().to_string();
    let target = create.target.clone();
    let created = client.create(create).await.expect("agent create");
    assert_eq!(created.status(), ContainerState::Created);
    assert_eq!(created.pid(), Some(101));
    assert_eq!(
        client
            .state(AgentStateRequest {
                target: target.clone()
            })
            .await
            .expect("agent state"),
        created
    );

    let running = client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("start-1")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("agent start");
    assert_eq!(running.status(), ContainerState::Running);

    let stopped = client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("kill-1")),
            target: target.clone(),
            signal: Signal::new(15).expect("signal"),
            all: false,
        })
        .await
        .expect("agent kill");
    assert_eq!(stopped.status(), ContainerState::Stopped);

    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("delete-1")),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("agent delete");

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean server shutdown");
}

#[tokio::test]
async fn protocol_nine_round_trips_generation_fenced_filesystem_requests() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(33));
    let client = AgentClient::connect_for_test(host, token(33), 9, 9)
        .await
        .expect("connect protocol-nine agent client");
    assert!(client
        .hello()
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::File));
    assert!(client
        .hello()
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::Filesystem));

    let create = create_request_for("filesystem-container", 5, "filesystem-create");
    let target = create.target.clone();
    client.create(create).await.expect("agent create");
    let upload = client
        .file(FileRequest {
            target: target.clone(),
            op: FileOp::Upload,
            path: "/agent.txt".to_string(),
            data: Some(String::new()),
            user: None,
            context: Some(OperationContext::new(operation_id("filesystem-upload"))),
        })
        .await
        .expect("agent file upload");
    assert_eq!(upload.target, target);
    assert_eq!(upload.size, 0);

    let listed = client
        .filesystem(FilesystemRequest {
            target: target.clone(),
            op: FilesystemOp::ListDir,
            path: "/".to_string(),
            destination: None,
            depth: 1,
            user: None,
            context: None,
        })
        .await
        .expect("agent filesystem listing");
    assert_eq!(listed.target, target);
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].path, "/agent.txt");

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean server shutdown");
}

#[tokio::test]
async fn explicit_close_is_clone_wide_idempotent_and_stops_the_server() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(31));
    let client = AgentClient::connect(host, token(31))
        .await
        .expect("connect agent client");
    let clone = client.clone();

    client.close().await.expect("close shared connection");
    clone.close().await.expect("repeat close through clone");
    let error = clone
        .state(AgentStateRequest {
            target: create_request().target,
        })
        .await
        .expect_err("closed clone must reject later dispatch");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.message.contains("explicitly closed"));

    server
        .await
        .expect("server task")
        .expect("explicit client close must stop the server cleanly");
}

#[tokio::test]
async fn explicit_close_drops_the_transport_while_client_clones_remain() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let dropped = Arc::new(AtomicBool::new(false));
    let host = DropObservedStream::new(host, Arc::clone(&dropped));
    let server = spawn_server(guest, token(32));
    let client = AgentClient::connect(host, token(32))
        .await
        .expect("connect agent client");
    let clone = client.clone();

    assert!(!dropped.load(Ordering::SeqCst));
    client.close().await.expect("close shared connection");
    assert!(
        dropped.load(Ordering::SeqCst),
        "close must release the transport even while client clones remain"
    );
    clone.close().await.expect("repeat close through clone");

    server
        .await
        .expect("server task")
        .expect("transport drop must stop the server cleanly");
}

#[tokio::test]
async fn explicit_close_waits_for_an_in_flight_request_before_closing_the_stream() {
    let (host, mut guest) = tokio::io::duplex(1024 * 1024);
    let (request_seen_send, request_seen_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let _hello: HostHello = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing hello"))?;
        write_frame(
            &mut guest,
            &HelloOutcome::Accepted {
                hello: AgentHello::new(
                    1,
                    AgentCapabilities::core("close-test", std::env::consts::ARCH)?,
                ),
            },
        )
        .await?;
        let request: RequestEnvelope = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing create request"))?;
        let AgentRequest::Create(create) = request.request else {
            return Err(Error::new(ErrorCode::Internal, "expected create request"));
        };
        request_seen_send
            .send(())
            .map_err(|()| Error::new(ErrorCode::Internal, "request observer disappeared"))?;
        release_receive
            .await
            .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
        let state = AgentState::new(
            create.target,
            ContainerState::Created,
            Some(101),
            create.bundle.config_digest(),
        )?;
        write_frame(
            &mut guest,
            &ResponseEnvelope {
                version: 1,
                request_id: request.request_id,
                outcome: ResponseOutcome::Succeeded {
                    response: Box::new(AgentResponse::State(state)),
                },
            },
        )
        .await?;
        let after_close = read_frame::<RequestEnvelope, _>(&mut guest).await?;
        if after_close.is_some() {
            return Err(Error::new(
                ErrorCode::Internal,
                "client dispatched a request after explicit close",
            ));
        }
        Ok::<_, Error>(())
    });

    let client = AgentClient::connect(host, token(32))
        .await
        .expect("connect agent client");
    let request_client = client.clone();
    let request = tokio::spawn(async move { request_client.create(create_request()).await });
    request_seen_receive
        .await
        .expect("server must observe in-flight request");
    let close_client = client.clone();
    let close = tokio::spawn(async move { close_client.close().await });
    tokio::task::yield_now().await;
    assert!(
        !close.is_finished(),
        "close must wait for the in-flight request"
    );
    release_send.send(()).expect("release in-flight request");
    request
        .await
        .expect("request task")
        .expect("in-flight request must finish before close");
    close
        .await
        .expect("close task")
        .expect("close shared connection");
    server
        .await
        .expect("server task")
        .expect("server must observe transport close");
}

#[tokio::test]
async fn protocol_v2_wait_returns_and_replays_the_exact_exit_status() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(18));
    let client = AgentClient::connect_for_test(host, token(18), 2, 2)
        .await
        .expect("connect protocol-v2 client");
    assert_eq!(client.hello().selected_version(), 2);
    assert_eq!(
        client.hello().capabilities().operations(),
        &[
            crate::AgentOperation::Create,
            crate::AgentOperation::State,
            crate::AgentOperation::Start,
            crate::AgentOperation::Kill,
            crate::AgentOperation::Delete,
            crate::AgentOperation::Wait,
        ]
    );

    let create = create_request_for("wait-container", 1, "wait-create");
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    client.create(create).await.expect("create wait container");
    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("wait-start")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("start wait container");
    client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("wait-kill")),
            target: target.clone(),
            signal: Signal::new(9).expect("signal"),
            all: false,
        })
        .await
        .expect("kill wait container");
    let request = AgentWaitRequest {
        target: target.clone(),
        timeout_ms: Some(1_000),
    };
    let expected = ExitStatus::signaled(9, false).expect("exit status");
    assert_eq!(
        client.wait(request.clone()).await.expect("first wait"),
        expected
    );
    assert_eq!(client.wait(request).await.expect("repeated wait"), expected);

    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("wait-delete")),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete wait container");
    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v2 server shutdown");
}

#[tokio::test]
async fn protocol_v1_rejects_a_forged_wait_before_service_dispatch() {
    let (mut host, guest) = tokio::io::duplex(64 * 1024);
    let agent = Arc::new(TestAgent::default());
    let expected_token = token(19);
    let server = spawn_server_with_agent(guest, expected_token.clone(), agent.clone());

    write_frame(
        &mut host,
        &HostHello {
            protocols: ProtocolRange { min: 1, max: 1 },
            token: expected_token,
        },
    )
    .await
    .expect("write protocol-v1 hello");
    let hello: HelloOutcome = read_frame(&mut host)
        .await
        .expect("read protocol-v1 hello")
        .expect("server returned protocol-v1 hello");
    let HelloOutcome::Accepted { hello } = hello else {
        panic!("protocol-v1 negotiation was rejected");
    };
    assert_eq!(hello.selected_version(), 1);
    assert!(!hello
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::Wait));

    write_frame(
        &mut host,
        &RequestEnvelope {
            version: 1,
            request_id: 41,
            request: AgentRequest::Wait(AgentWaitRequest {
                target: ContainerTarget::exact(container_id("forged-wait"), Generation(1)),
                timeout_ms: Some(1),
            }),
        },
    )
    .await
    .expect("write forged protocol-v1 wait");
    let response: ResponseEnvelope = read_frame(&mut host)
        .await
        .expect("read forged wait response")
        .expect("server returned forged wait response");
    assert_eq!(response.version, 1);
    assert_eq!(response.request_id, 41);
    let ResponseOutcome::Failed { error } = response.outcome else {
        panic!("forged protocol-v1 wait unexpectedly succeeded");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(agent.wait_dispatches.load(Ordering::SeqCst), 0);

    drop(host);
    server
        .await
        .expect("server task")
        .expect("clean protocol-v1 server shutdown");
}

#[tokio::test]
async fn transports_two_independently_fenced_container_generations() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(17));
    let client = AgentClient::connect(host, token(17))
        .await
        .expect("connect multi-container client");

    let create_a = create_request_for("multi-a", 1, "multi-create-a-1");
    let create_b = create_request_for("multi-b", 1, "multi-create-b-1");
    let target_a1 = create_a.target.clone();
    let target_b = create_b.target.clone();
    let digest_a = create_a.bundle.config_digest().to_string();
    let digest_b = create_b.bundle.config_digest().to_string();
    let created_a = client.create(create_a).await.expect("create container A");
    let created_b = client.create(create_b).await.expect("create container B");
    assert_eq!(created_a.status(), ContainerState::Created);
    assert_eq!(created_b.status(), ContainerState::Created);
    assert!(created_a.pid().is_some_and(|pid| pid > 0));
    assert!(created_b.pid().is_some_and(|pid| pid > 0));
    assert_ne!(created_a.pid(), created_b.pid());

    let running_a = client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("multi-start-a-1")),
            target: target_a1.clone(),
            expected_config_digest: digest_a,
        })
        .await
        .expect("start container A");
    assert_eq!(running_a.status(), ContainerState::Running);
    assert_eq!(
        client
            .state(AgentStateRequest {
                target: target_b.clone()
            })
            .await
            .expect("container B remains visible"),
        created_b
    );

    client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("multi-kill-a-1")),
            target: target_a1.clone(),
            signal: Signal::new(15).expect("signal"),
            all: false,
        })
        .await
        .expect("kill container A");
    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("multi-delete-a-1")),
            target: target_a1.clone(),
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete container A");
    assert_eq!(
        client
            .state(AgentStateRequest {
                target: target_b.clone()
            })
            .await
            .expect("container B survives A delete"),
        created_b
    );

    let stale = client
        .create(create_request_for("multi-a", 1, "multi-stale-a-1"))
        .await
        .expect_err("stale generation must fail");
    assert_eq!(stale.code, ErrorCode::Conflict);
    let create_a2 = create_request_for("multi-a", 2, "multi-create-a-2");
    let target_a2 = create_a2.target.clone();
    let recreated_a = client
        .create(create_a2)
        .await
        .expect("recreate container A");
    assert_eq!(recreated_a.status(), ContainerState::Created);
    let stale_state = client
        .state(AgentStateRequest { target: target_a1 })
        .await
        .expect_err("old generation must remain fenced");
    assert_eq!(stale_state.code, ErrorCode::Conflict);
    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("multi-delete-a-2")),
            target: target_a2,
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete recreated container A");

    client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("multi-start-b-1")),
            target: target_b.clone(),
            expected_config_digest: digest_b,
        })
        .await
        .expect("start container B");
    client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("multi-kill-b-1")),
            target: target_b.clone(),
            signal: Signal::new(15).expect("signal"),
            all: false,
        })
        .await
        .expect("kill container B");
    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("multi-delete-b-1")),
            target: target_b,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete container B");

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean multi-container server shutdown");
}

#[tokio::test]
async fn rejects_wrong_session_tokens_and_incompatible_versions() {
    let (host, guest) = tokio::io::duplex(64 * 1024);
    let server = spawn_server(guest, token(7));
    let error = AgentClient::connect(host, token(8))
        .await
        .expect_err("wrong token must fail");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        server
            .await
            .expect("server task")
            .expect_err("server rejects token")
            .code,
        ErrorCode::PermissionDenied
    );

    let (host, guest) = tokio::io::duplex(64 * 1024);
    let server = spawn_server(guest, token(9));
    let error = AgentClient::connect_for_test(host, token(9), 10, 10)
        .await
        .expect_err("incompatible version must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        server
            .await
            .expect("server task")
            .expect_err("server rejects version")
            .code,
        ErrorCode::FailedPrecondition
    );
}

#[tokio::test]
async fn rejects_oversized_frames_before_reading_the_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&11_u32.to_be_bytes())
        .await
        .expect("write frame header");

    let error = read_frame_for_test::<serde_json::Value, _>(&mut reader, 10)
        .await
        .expect_err("oversized frame must fail from its header");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn rejects_tampered_bundle_digests_before_guest_dispatch() {
    let mut encoded = serde_json::to_value(create_request()).expect("encode request");
    encoded["bundle"]["configDigest"] =
        serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
    let request: AgentCreateRequest = serde_json::from_value(encoded).expect("decode request");
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(10));
    let client = AgentClient::connect(host, token(10))
        .await
        .expect("connect agent client");

    let error = client
        .create(request)
        .await
        .expect_err("tampered digest must fail locally");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean server shutdown");
}

#[tokio::test]
async fn correlation_failure_permanently_poisoned_the_client_connection() {
    let (host, mut guest) = tokio::io::duplex(1024 * 1024);
    let dropped = Arc::new(AtomicBool::new(false));
    let host = DropObservedStream::new(host, Arc::clone(&dropped));
    let malicious = tokio::spawn(async move {
        let hello: HostHello = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing hello"))?;
        let capabilities = AgentCapabilities::core("malicious-test", std::env::consts::ARCH)?;
        write_frame(
            &mut guest,
            &HelloOutcome::Accepted {
                hello: AgentHello::new(1, capabilities),
            },
        )
        .await?;
        let request: RequestEnvelope = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing request"))?;
        let AgentRequest::Create(create) = request.request else {
            return Err(Error::new(ErrorCode::Internal, "expected create"));
        };
        let state = AgentState::new(
            create.target,
            ContainerState::Created,
            Some(101),
            create.bundle.config_digest(),
        )?;
        write_frame(
            &mut guest,
            &ResponseEnvelope {
                version: 1,
                request_id: request.request_id + 1,
                outcome: ResponseOutcome::Succeeded {
                    response: Box::new(AgentResponse::State(state)),
                },
            },
        )
        .await?;
        let _ = hello;
        Ok::<_, Error>(())
    });

    let client = AgentClient::connect(host, token(11))
        .await
        .expect("connect malicious peer");
    let clone = client.clone();
    let error = client
        .create(create_request())
        .await
        .expect_err("mismatched response ID must fail");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(
        dropped.load(Ordering::SeqCst),
        "correlation failure must release the transport even while clones remain"
    );
    let error = clone
        .create(create_request())
        .await
        .expect_err("connection must stay poisoned");
    assert_eq!(error.code, ErrorCode::Unavailable);
    clone.close().await.expect("close poisoned client");
    malicious
        .await
        .expect("malicious task")
        .expect("malicious response written");
}

#[test]
fn secrets_are_redacted_and_guest_paths_are_normalized() {
    assert_eq!(format!("{:?}", token(12)), "SessionToken([REDACTED])");
    for path in [
        "run/a3s",
        "/run//a3s",
        "/run/../a3s",
        "/run/./a3s",
        "/run/a3s/",
        r"/run\a3s",
    ] {
        assert!(GuestPath::new(path).is_err(), "{path:?} must be rejected");
    }
    assert!(GuestPath::new("/run/a3s").is_ok());
}
