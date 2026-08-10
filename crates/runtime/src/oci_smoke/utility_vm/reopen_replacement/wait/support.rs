use super::*;

pub(super) async fn shutdown_setup_failure(
    service: crate::HostRuntimeService,
    driver: Arc<QualificationHvfDriver>,
    cleanup: MacosHostCleanupTracker,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> std::result::Result<(), String> {
    drop(service);
    report.first_vm = driver.shutdown().await;
    cleanup.apply(&mut report.first_vm).await;
    Err(reason)
}

pub(super) fn identity_or_expected(
    identity: std::result::Result<(OperationId, ContainerTarget), String>,
    failure: &mut Option<String>,
    expected: (OperationId, ContainerTarget),
) -> (OperationId, ContainerTarget) {
    match identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(failure, reason);
            expected
        }
    }
}

pub(super) async fn init_exit_cache(
    state_root: &Path,
    target: &ContainerTarget,
) -> std::result::Result<Option<ExitStatus>, String> {
    let path = state_root
        .join("containers")
        .join(target.id.as_str())
        .join("record.json");
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable Wait container record {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable Wait container record {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.generation)
        .map_err(|error| format!("failed to encode expected Wait generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some("a3s.oci.container-record.v1")
        && value.get("id").and_then(serde_json::Value::as_str) == Some(target.id.as_str())
        && value
            .get("record")
            .and_then(|record| record.get("generation"))
            == Some(&expected_generation);
    if !identity_matches {
        return Err(format!(
            "durable Wait container record {} did not match the exact generation",
            path.display()
        ));
    }
    match value.get("initExitStatus") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(status) => serde_json::from_value(status.clone())
            .map(Some)
            .map_err(|error| {
                format!(
                    "failed to decode durable init exit cache {}: {error}",
                    path.display()
                )
            }),
    }
}

pub(super) fn operation_id(value: &str) -> std::result::Result<OperationId, String> {
    OperationId::new(value)
        .map_err(|error| format!("failed to construct Wait qualification operation ID: {error}"))
}

pub(super) fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first owner returned an unexpected Wait transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ContainerId, ContainerTarget, ExitStatus, Generation};
    use serde_json::json;

    use super::init_exit_cache;

    #[tokio::test]
    async fn durable_wait_cache_reader_requires_the_exact_generation() {
        let temporary = tempfile::tempdir().expect("temporary state root");
        let id = ContainerId::new("wait-cache-reader").expect("container ID");
        let target = ContainerTarget::exact(id.clone(), Generation(7));
        let container_directory = temporary.path().join("containers").join(id.as_str());
        tokio::fs::create_dir_all(&container_directory)
            .await
            .expect("container state directory");
        let record_path = container_directory.join("record.json");
        let expected = ExitStatus::signaled(9, false).expect("signal exit status");
        tokio::fs::write(
            &record_path,
            serde_json::to_vec(&json!({
                "schemaVersion": "a3s.oci.container-record.v1",
                "id": id.as_str(),
                "record": { "generation": 7 },
                "initExitStatus": expected,
            }))
            .expect("encode cached record"),
        )
        .await
        .expect("write cached record");
        assert_eq!(
            init_exit_cache(temporary.path(), &target)
                .await
                .expect("read exact cache"),
            Some(ExitStatus::signaled(9, false).expect("expected exit"))
        );

        tokio::fs::write(
            &record_path,
            serde_json::to_vec(&json!({
                "schemaVersion": "a3s.oci.container-record.v1",
                "id": target.id.as_str(),
                "record": { "generation": 7 },
            }))
            .expect("encode uncached record"),
        )
        .await
        .expect("write uncached record");
        assert_eq!(
            init_exit_cache(temporary.path(), &target)
                .await
                .expect("read empty cache"),
            None
        );

        let stale = ContainerTarget::exact(target.id.clone(), Generation(8));
        assert!(init_exit_cache(temporary.path(), &stale).await.is_err());
    }
}
