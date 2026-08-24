use super::*;

impl Service {
    pub(super) async fn delete_task(&self, task_id: String) -> TtrpcResult<api::DeleteResponse> {
        let snapshot = {
            let state = self.state.lock().await;
            if let Some(task) = state.tasks.get(&task_id) {
                task.clone()
            } else {
                let restore_error = state.restore_error.clone();
                drop(state);
                if ShimMetadata::load(&self.metadata_path())
                    .map_err(runtime_error)?
                    .is_some()
                {
                    return Err(restore_error.map_or_else(
                        || {
                            runtime_error(
                                RuntimeError::new(
                                    ErrorCode::FailedPrecondition,
                                    format!(
                                        "task {task_id} retains metadata while its delete cleanup is incomplete"
                                    ),
                                )
                                .for_operation("containerd-delete-task-replay"),
                            )
                        },
                        runtime_error,
                    ));
                }
                let receipt = TaskDeleteReceipt::load(&self.bundle)
                    .map_err(runtime_error)?
                    .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
                receipt
                    .validate_for_service(&self.namespace, &task_id, &self.bundle)
                    .map_err(runtime_error)?;
                let (response, _) = task_delete_response(&receipt).map_err(runtime_error)?;
                // This replay-only service has no live task for containerd to
                // shut down. Exit after returning the durable response so a
                // manually rehydrated shim cannot survive daemon cleanup as
                // an unowned process.
                self.exit.signal();
                return Ok(response);
            }
        };
        let adapter = self.adapter().await.map_err(runtime_error)?;
        // Stop all FIFO readers before reserving delete so no new stdin/EOF
        // mutation can race the runtime's active-process gate. Already-issued
        // mutations remain cancellation-safe and delete retries the same
        // durable identity until those claims finish or the bounded deadline
        // expires.
        self.stop_task_pumps(&task_id).await;
        let pid = record_pid(&snapshot.record);
        let code = snapshot.exit.as_ref().map_or(0, adapter::exit_code);
        let retained_receipt =
            match TaskDeleteReceipt::load(&snapshot.bundle).map_err(runtime_error)? {
                Some(receipt)
                    if receipt
                        .matches_for(
                            &snapshot.identity,
                            snapshot.record.generation,
                            &snapshot.bundle,
                        )
                        .map_err(runtime_error)? =>
                {
                    Some(receipt)
                }
                Some(_) => {
                    TaskDeleteReceipt::remove(&snapshot.bundle).map_err(runtime_error)?;
                    None
                }
                None => None,
            };
        let receipt = if let Some(receipt) = retained_receipt {
            receipt
                .validate_for(
                    &snapshot.identity,
                    snapshot.record.generation,
                    &snapshot.bundle,
                )
                .map_err(runtime_error)?;
            let exited_at_matches = snapshot.exited_at.is_none_or(|exited_at| {
                system_time_to_unix_nanos(exited_at) == Some(receipt.exited_at_unix_nanos())
            });
            if receipt.pid() != pid || receipt.exit_status() != code || !exited_at_matches {
                return Err(runtime_error(
                    RuntimeError::new(
                        ErrorCode::Conflict,
                        format!(
                            "task {task_id} terminal response changed after its delete receipt was prepared"
                        ),
                    )
                    .for_operation("containerd-delete-task-prepare"),
                ));
            }
            receipt
        } else {
            let exited_at = snapshot.exited_at.unwrap_or_else(SystemTime::now);
            TaskDeleteReceipt::new(
                &snapshot.bundle,
                &snapshot.identity,
                snapshot.record.generation,
                pid,
                code,
                system_time_to_unix_nanos(exited_at).ok_or_else(|| {
                    runtime_error(
                        RuntimeError::new(
                            ErrorCode::FailedPrecondition,
                            format!(
                                "containerd task {task_id} records an unrepresentable exit time"
                            ),
                        )
                        .for_operation("containerd-delete-task-prepare"),
                    )
                })?,
            )
            .map_err(runtime_error)?
        };
        receipt.store().map_err(runtime_error)?;
        adapter
            .delete(&snapshot.identity, snapshot.record.generation, false)
            .await
            .map_err(runtime_error)?;
        self.stop_task_monitors(&task_id).await;
        let _metadata_guard = self.metadata_gate.lock().await;
        let current = self
            .state
            .lock()
            .await
            .tasks
            .get(&task_id)
            .cloned()
            .ok_or_else(|| ttrpc_error(format!("task {task_id} disappeared during delete")))?;
        if current.identity != snapshot.identity
            || current.record.generation != snapshot.record.generation
            || current.bundle != snapshot.bundle
        {
            return Err(runtime_error(
                RuntimeError::new(
                    ErrorCode::Conflict,
                    format!("task {task_id} identity changed during delete"),
                )
                .for_operation("containerd-delete-task-commit"),
            ));
        }
        ShimCreateIntent::remove(&snapshot.bundle).map_err(runtime_error)?;
        if snapshot.rootfs_mounted {
            Self::unmount_rootfs(snapshot.bundle.join("rootfs")).await?;
        }
        ExecDeleteJournal::remove(&snapshot.bundle).map_err(runtime_error)?;
        ShimMetadata::remove(&snapshot.bundle).map_err(runtime_error)?;
        self.state.lock().await.tasks.remove(&task_id);
        let (response, exited_at) = task_delete_response(&receipt).map_err(runtime_error)?;
        self.publish_delete(&task_id, None, pid, code, exited_at)
            .await;
        Ok(response)
    }
}
