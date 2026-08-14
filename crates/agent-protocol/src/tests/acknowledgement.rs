use super::*;

#[tokio::test]
async fn protocol_v10_routes_bounded_operation_acknowledgements() {
    let agent = Arc::new(TestAgent::default());
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server_with_agent(guest, token(71), Arc::clone(&agent));
    let client = AgentClient::connect_for_test(host, token(71), 10, 10)
        .await
        .expect("connect protocol-v10 client");
    assert_eq!(client.hello().selected_version(), 10);
    assert_eq!(
        client.hello().capabilities().operations().last(),
        Some(&crate::AgentOperation::AcknowledgeOperations)
    );
    let operation_ids = vec![
        operation_id("acknowledge-first"),
        operation_id("acknowledge-second"),
    ];

    client
        .acknowledge_operations(&operation_ids)
        .await
        .expect("acknowledge completed guest operations");

    assert_eq!(
        *agent
            .acknowledgements
            .lock()
            .expect("captured acknowledgements"),
        vec![operation_ids]
    );
    client.close().await.expect("close protocol-v10 client");
    server
        .await
        .expect("protocol-v10 server task")
        .expect("clean protocol-v10 server shutdown");
}

#[tokio::test]
async fn pre_v10_clients_preserve_the_acknowledgement_noop() {
    let agent = Arc::new(TestAgent::default());
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server_with_agent(guest, token(72), Arc::clone(&agent));
    let client = AgentClient::connect_for_test(host, token(72), 9, 9)
        .await
        .expect("connect protocol-v9 client");
    assert!(!client
        .hello()
        .capabilities()
        .operations()
        .contains(&crate::AgentOperation::AcknowledgeOperations));

    client
        .acknowledge_operations(&[operation_id("legacy-acknowledgement")])
        .await
        .expect("legacy acknowledgement compatibility");

    assert!(agent
        .acknowledgements
        .lock()
        .expect("captured legacy acknowledgements")
        .is_empty());
    client.close().await.expect("close protocol-v9 client");
    server
        .await
        .expect("protocol-v9 server task")
        .expect("clean protocol-v9 server shutdown");
}

#[test]
fn acknowledgement_validation_is_nonempty_unique_and_bounded() {
    let empty = AgentRequest::AcknowledgeOperations(AgentAcknowledgeOperationsRequest {
        operation_ids: Vec::new(),
    });
    assert_eq!(
        empty
            .validate()
            .expect_err("empty acknowledgement must fail")
            .code,
        ErrorCode::InvalidArgument
    );

    let duplicate_id = operation_id("duplicate-acknowledgement");
    let duplicate = AgentRequest::AcknowledgeOperations(AgentAcknowledgeOperationsRequest {
        operation_ids: vec![duplicate_id.clone(), duplicate_id],
    });
    assert_eq!(
        duplicate
            .validate()
            .expect_err("duplicate acknowledgement must fail")
            .code,
        ErrorCode::InvalidArgument
    );

    let bounded = (0..crate::AGENT_MAX_ACKNOWLEDGED_OPERATIONS)
        .map(|index| operation_id(&format!("bounded-acknowledgement-{index}")))
        .collect::<Vec<_>>();
    AgentRequest::AcknowledgeOperations(AgentAcknowledgeOperationsRequest {
        operation_ids: bounded.clone(),
    })
    .validate()
    .expect("maximum acknowledgement batch");
    let mut oversized = bounded;
    oversized.push(operation_id("oversized-acknowledgement"));
    assert_eq!(
        AgentRequest::AcknowledgeOperations(AgentAcknowledgeOperationsRequest {
            operation_ids: oversized,
        })
        .validate()
        .expect_err("oversized acknowledgement must fail")
        .code,
        ErrorCode::ResourceExhausted
    );
}
