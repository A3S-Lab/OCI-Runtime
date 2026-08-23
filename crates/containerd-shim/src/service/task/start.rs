use super::*;

impl Service {
    pub(super) async fn start_task(
        &self,
        req: api::StartRequest,
    ) -> TtrpcResult<api::StartResponse> {
        let task_id = req.id().to_string();
        let exec_id = req.exec_id().to_string();
        let snapshot = self.task_snapshot(&task_id).await?;
        let pid = if exec_id.is_empty() {
            let adapter = self.adapter().await.map_err(runtime_error)?;
            let publish_started = adapter::task_status(&snapshot.record) == 1;
            let record = adapter
                .start(&snapshot.identity, snapshot.record.generation)
                .await
                .map_err(runtime_error)?;
            let pid = record_pid(&record);
            let mut state = self.state.lock().await;
            state
                .tasks
                .get_mut(&task_id)
                .ok_or_else(|| ttrpc_error(format!("task {task_id} disappeared")))?
                .record = record;
            state
                .pumps
                .get(&Self::pump_key(&task_id, None))
                .ok_or_else(|| {
                    ttrpc_error(format!("task {task_id} I/O pump disappeared during Start"))
                })?
                .activate_stdin();
            drop(state);
            self.persist_task(&task_id).await?;
            self.exit_notify.notify_waiters();
            if publish_started {
                self.publish_start(&task_id, pid).await;
            }
            self.ensure_exit_monitor(&task_id, None).await;
            pid
        } else {
            let exec = snapshot
                .execs
                .get(&exec_id)
                .cloned()
                .ok_or_else(|| ttrpc_error(format!("unknown exec {exec_id}")))?;
            let exec_identity = exec.identity(&exec_id).map_err(runtime_error)?;
            if exec.stage == ExecStage::Exited {
                return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                    ttrpc::Code::FAILED_PRECONDITION,
                    format!("exec {exec_id} has already exited"),
                )));
            }
            let publish_started = exec.stage != ExecStage::Started;
            if exec.stage == ExecStage::Added {
                let mut state = self.state.lock().await;
                state
                    .tasks
                    .get_mut(&task_id)
                    .and_then(|task| task.execs.get_mut(&exec_id))
                    .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?
                    .stage = ExecStage::Starting;
                drop(state);
                self.persist_task(&task_id).await?;
            }
            let adapter = self.adapter().await.map_err(runtime_error)?;
            let process = match adapter
                .process(
                    &snapshot.identity,
                    snapshot.record.generation,
                    &exec_identity,
                )
                .await
            {
                Ok(process) => process,
                Err(error) if error.code == ErrorCode::NotFound => adapter
                    .exec(
                        &snapshot.identity,
                        snapshot.record.generation,
                        &exec_identity,
                        exec.process,
                        adapter::process_io(
                            exec.terminal,
                            !exec.stdin.is_empty(),
                            !exec.stdout.is_empty(),
                            !exec.stderr.is_empty(),
                        ),
                    )
                    .await
                    .map_err(runtime_error)?,
                Err(error) => return Err(runtime_error(error)),
            };
            let pid = process.pid.unwrap_or(0);
            let needs_pumps = !self
                .state
                .lock()
                .await
                .pumps
                .contains_key(&Self::pump_key(&task_id, Some(&exec_id)));
            let pumps = if needs_pumps {
                Some(
                    io::start_process_pumps(
                        adapter.clone(),
                        snapshot.identity.clone(),
                        snapshot.record.generation,
                        Some(exec_identity.clone()),
                        ProcessIoEndpoints {
                            stdin: &exec.stdin,
                            stdout: &exec.stdout,
                            stderr: &exec.stderr,
                            terminal: exec.terminal,
                            await_start_activation: exec.stage == ExecStage::Added,
                            read_stdin_at_activation: exec.stage == ExecStage::Added,
                            stdin_sequence: exec.stdin_sequence,
                            pending_stdin_write: exec.pending_stdin_write.clone(),
                            stdin_close_state: exec.stdin_close_state,
                            stdin_journal: Some(self.stdin_journal(&task_id, Some(&exec_id))),
                            output_cursor: exec.output_cursor,
                            output_cursor_committer: Some(
                                self.output_cursor_committer(&task_id, Some(&exec_id)),
                            ),
                        },
                    )
                    .map_err(runtime_error)?,
                )
            } else {
                None
            };
            let mut state = self.state.lock().await;
            let exec_state = state
                .tasks
                .get_mut(&task_id)
                .and_then(|task| task.execs.get_mut(&exec_id));
            let Some(exec_state) = exec_state else {
                drop(state);
                if let Some(pumps) = pumps {
                    pumps.stop().await;
                }
                let _ = adapter
                    .signal_process(
                        &snapshot.identity,
                        snapshot.record.generation,
                        &exec_identity,
                        9,
                    )
                    .await;
                let _ = adapter
                    .wait_process(
                        &snapshot.identity,
                        snapshot.record.generation,
                        &exec_identity,
                    )
                    .await;
                return Err(ttrpc_error(format!("exec {exec_id} disappeared")));
            };
            exec_state.stage = ExecStage::Started;
            exec_state.record = Some(process);
            if let Some(pumps) = pumps {
                state
                    .pumps
                    .insert(Self::pump_key(&task_id, Some(&exec_id)), pumps);
            }
            state
                .pumps
                .get(&Self::pump_key(&task_id, Some(&exec_id)))
                .ok_or_else(|| {
                    ttrpc_error(format!("exec {exec_id} I/O pump disappeared during Start"))
                })?
                .activate_stdin();
            drop(state);
            self.persist_task(&task_id).await?;
            self.exit_notify.notify_waiters();
            if publish_started {
                self.publish_exec_started(&task_id, &exec_id, pid).await;
            }
            self.ensure_exit_monitor(&task_id, Some(&exec_id)).await;
            pid
        };
        let mut response = api::StartResponse::new();
        response.set_pid(pid);
        Ok(response)
    }
}
