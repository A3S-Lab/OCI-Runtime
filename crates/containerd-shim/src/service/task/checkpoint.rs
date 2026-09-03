use a3s_oci_sdk::CheckpointResponse;

use super::*;

impl Service {
    pub(super) async fn checkpoint_task(
        &self,
        req: api::CheckpointTaskRequest,
    ) -> TtrpcResult<api::Empty> {
        if req.id().is_empty() {
            return Err(ttrpc_invalid_argument(
                "containerd checkpoint task ID must not be empty".to_string(),
            ));
        }
        crate::checkpoint::validate_checkpoint_options(req.options.as_ref(), req.path())
            .map_err(runtime_error)?;

        let initial = self.task_snapshot(req.id()).await?;
        let control_gate = Arc::clone(&initial.control_gate);
        let _control_guard = control_gate.lock().await;
        let task = self.task_snapshot(req.id()).await?;
        if task.restore_state == RestoreState::PendingStart {
            return Err(runtime_error(
                RuntimeError::new(
                    ErrorCode::FailedPrecondition,
                    "a restored containerd task must pass its Start barrier before checkpointing",
                )
                .for_operation("containerd-checkpoint"),
            ));
        }
        if task.exit.is_some() || !task.record.is_paused() {
            return Err(runtime_error(
                RuntimeError::new(
                    ErrorCode::FailedPrecondition,
                    "containerd checkpoint requires an already-paused live task",
                )
                .for_operation("containerd-checkpoint"),
            ));
        }

        let destination = crate::checkpoint::CheckpointDestination::open(req.path())
            .await
            .map_err(runtime_error)?;
        if let Some(package) = destination.committed().await.map_err(runtime_error)? {
            CheckpointResponse::new(task.record.clone(), package.reference().clone())
                .map_err(runtime_error)?;
            self.publish_checkpointed(req.id(), req.path()).await;
            return Ok(api::Empty::new());
        }

        let adapter = self.adapter().await.map_err(runtime_error)?;
        let response = adapter
            .checkpoint(
                &task.identity,
                task.record.generation,
                destination.artifact_path().clone(),
            )
            .await
            .map_err(runtime_error)?;
        if response.source() != &task.record {
            return Err(runtime_error(
                RuntimeError::new(
                    ErrorCode::FailedPrecondition,
                    "runtime checkpoint response changed the exact paused task record",
                )
                .for_operation("containerd-checkpoint"),
            ));
        }
        destination
            .commit(response.reference().clone())
            .await
            .map_err(runtime_error)?;
        self.publish_checkpointed(req.id(), req.path()).await;
        Ok(api::Empty::new())
    }
}
