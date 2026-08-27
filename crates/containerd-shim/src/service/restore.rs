use a3s_oci_sdk::oci_spec::runtime::ContainerState;

use super::*;

const STOPPED_EXIT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(2);
type ProcessPumpSet = Vec<((String, String), ProcessPumps)>;

pub(super) async fn recover_stopped_init_exit(
    adapter: &RuntimeAdapter,
    task: &mut TaskState,
) -> Result<(), RuntimeError> {
    if task.exit.is_some() || *task.record.state.status() != ContainerState::Stopped {
        return Ok(());
    }

    let exit = tokio::time::timeout(
        STOPPED_EXIT_RECOVERY_TIMEOUT,
        adapter.wait(&task.identity, task.record.generation),
    )
    .await
    .map_err(|_| {
        RuntimeError::new(
            ErrorCode::DeadlineExceeded,
            format!(
                "runtime generation {} reported Stopped without returning its durable init exit within {} seconds",
                task.record.generation.0,
                STOPPED_EXIT_RECOVERY_TIMEOUT.as_secs()
            ),
        )
        .for_operation("containerd-shim-rehydrate-exit")
    })??;
    task.exit = Some(exit);
    task.exited_at = Some(SystemTime::now());
    Ok(())
}

pub(super) async fn recover_pending_exec_signal_exits(
    adapter: &RuntimeAdapter,
    task: &mut TaskState,
) -> Result<(), RuntimeError> {
    let exec_ids = task
        .execs
        .iter()
        .filter(|(_, exec)| {
            exec.stage == ExecStage::Started
                && exec.record.is_some()
                && exec.exit.is_none()
                && exec.pending_signal.is_some()
        })
        .map(|(exec_id, _)| exec_id.clone())
        .collect::<Vec<_>>();

    for exec_id in exec_ids {
        let exec_identity = task
            .execs
            .get(&exec_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    ErrorCode::Internal,
                    format!("containerd exec {exec_id} disappeared during exit recovery"),
                )
                .for_operation("containerd-shim-rehydrate-exec-exit")
            })?
            .identity(&exec_id)?;
        let Some(exit) = adapter
            .poll_process_exit(&task.identity, task.record.generation, &exec_identity)
            .await?
        else {
            continue;
        };
        let exec = task.execs.get_mut(&exec_id).ok_or_else(|| {
            RuntimeError::new(
                ErrorCode::Internal,
                format!("containerd exec {exec_id} disappeared before exit recovery commit"),
            )
            .for_operation("containerd-shim-rehydrate-exec-exit")
        })?;
        exec.stage = ExecStage::Exited;
        exec.exit = Some(exit);
        exec.exited_at = Some(SystemTime::now());
    }
    Ok(())
}

impl Service {
    pub(super) async fn restore_task(&self, expected_task_id: &str) -> Result<(), RuntimeError> {
        let Some(metadata) = ShimMetadata::load(&self.metadata_path())? else {
            return Ok(());
        };
        let identity = metadata.identity()?;
        if identity.namespace != self.namespace || identity.task_id != expected_task_id {
            return Err(RuntimeError::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "shim metadata belongs to {}/{}, but this shim serves {}/{}",
                    identity.namespace, identity.task_id, self.namespace, expected_task_id
                ),
            )
            .for_operation("containerd-shim-rehydrate"));
        }
        let task_delete_receipt = match TaskDeleteReceipt::load(metadata.bundle())? {
            Some(receipt)
                if receipt.matches_for(&identity, metadata.generation(), metadata.bundle())? =>
            {
                Some(receipt)
            }
            Some(_) => {
                TaskDeleteReceipt::remove(metadata.bundle())?;
                None
            }
            None => None,
        };
        let mut delete_journal =
            ExecDeleteJournal::load_or_new(metadata.bundle(), &identity, metadata.generation())?;
        let mut delete_journal_changed = false;
        for exec in metadata.execs() {
            delete_journal_changed |= delete_journal.remove_receipt(&exec.exec_id);
        }
        if delete_journal_changed {
            delete_journal.store()?;
        }
        let adapter = self.adapter().await?;
        let record = adapter
            .exact_state(&identity, metadata.generation())
            .await?;
        if record.generation != metadata.generation()
            || record.driver != metadata.driver()
            || record.isolation != metadata.isolation()
        {
            return Err(RuntimeError::new(
                ErrorCode::FailedPrecondition,
                "runtime state no longer matches the persisted containerd shim generation, driver, or isolation",
            )
            .for_operation("containerd-shim-rehydrate"));
        }
        let restore_state = if metadata.restore_state() == RestoreState::PendingStart {
            if *record.state.status() != ContainerState::Running {
                return Err(RuntimeError::new(
                    ErrorCode::FailedPrecondition,
                    "pending containerd restore no longer names a running generation",
                )
                .for_operation("containerd-shim-rehydrate"));
            }
            if record.is_paused() {
                RestoreState::PendingStart
            } else {
                // Resume is operation-idempotent. An unpaused exact generation
                // proves that the restore Start effect committed before the
                // shim could durably advance its local barrier state.
                RestoreState::Started
            }
        } else {
            metadata.restore_state()
        };
        if task_delete_receipt.is_some() {
            TaskDeleteReceipt::remove(metadata.bundle())?;
        }
        let mut task = TaskState {
            identity: identity.clone(),
            bundle: metadata.bundle().to_path_buf(),
            stdin: metadata.stdin().to_string(),
            stdout: metadata.stdout().to_string(),
            stderr: metadata.stderr().to_string(),
            terminal: metadata.terminal(),
            restore_state,
            stdin_sequence: metadata.stdin_sequence(),
            pending_stdin_write: metadata.pending_stdin_write().cloned(),
            stdin_close_state: metadata.stdin_close_state(),
            resize_gate: Arc::new(Mutex::new(())),
            resize_sequence: metadata.resize_sequence(),
            pending_resize: metadata.pending_resize().cloned(),
            terminal_size: metadata.terminal_size(),
            signal_gate: Arc::new(Mutex::new(())),
            signal_sequence: metadata.signal_sequence(),
            pending_signal: metadata.pending_signal().cloned(),
            output_cursor: metadata.output_cursor(),
            control_gate: Arc::new(Mutex::new(())),
            control_sequence: metadata.control_sequence(),
            pending_control: metadata.pending_control().cloned(),
            last_update_digest: metadata.last_update_digest().map(str::to_string),
            rootfs_mounted: metadata.rootfs_mounted(),
            record,
            exit: metadata.exit().cloned(),
            exited_at: metadata
                .exited_at_unix_nanos()
                .and_then(system_time_from_unix_nanos),
            exec_sequence: metadata.exec_sequence(),
            execs: BTreeMap::new(),
        };
        for exec in metadata.execs() {
            task.execs.insert(
                exec.exec_id.clone(),
                ExecState {
                    incarnation: exec.incarnation,
                    process: exec.process.clone(),
                    stdin: exec.stdin.clone(),
                    stdout: exec.stdout.clone(),
                    stderr: exec.stderr.clone(),
                    terminal: exec.terminal,
                    stdin_sequence: exec.stdin_sequence,
                    pending_stdin_write: exec.pending_stdin_write.clone(),
                    stdin_close_state: exec.stdin_close_state,
                    resize_gate: Arc::new(Mutex::new(())),
                    resize_sequence: exec.resize_sequence,
                    pending_resize: exec.pending_resize.clone(),
                    terminal_size: exec.terminal_size,
                    signal_gate: Arc::new(Mutex::new(())),
                    signal_sequence: exec.signal_sequence,
                    pending_signal: exec.pending_signal.clone(),
                    output_cursor: exec.output_cursor,
                    stage: exec.stage,
                    record: exec.record.clone(),
                    exit: exec.exit.clone(),
                    exited_at: exec
                        .exited_at_unix_nanos
                        .and_then(system_time_from_unix_nanos),
                },
            );
        }
        recover_stopped_init_exit(&adapter, &mut task).await?;
        recover_pending_exec_signal_exits(&adapter, &mut task).await?;
        control::replay_pending(&adapter, &mut task).await?;
        signal::replay_pending(&adapter, &mut task).await?;
        resize::replay_pending(&adapter, &mut task).await?;
        let exec_ids = task.execs.keys().cloned().collect::<Vec<_>>();
        for exec_id in exec_ids {
            let exec = task.execs.get(&exec_id).cloned().ok_or_else(|| {
                RuntimeError::new(
                    ErrorCode::Internal,
                    format!("exec {exec_id} disappeared during shim rehydration"),
                )
                .for_operation("containerd-shim-rehydrate")
            })?;
            if matches!(exec.stage, ExecStage::Starting | ExecStage::Started) && exec.exit.is_none()
            {
                let exec_identity = exec.identity(&exec_id)?;
                let process = match adapter
                    .process(&identity, task.record.generation, &exec_identity)
                    .await
                {
                    Ok(process) => process,
                    Err(error) if error.code == ErrorCode::NotFound => {
                        adapter
                            .exec(
                                &identity,
                                task.record.generation,
                                &exec_identity,
                                exec.process.clone(),
                                adapter::process_io(
                                    exec.terminal,
                                    !exec.stdin.is_empty(),
                                    !exec.stdout.is_empty(),
                                    !exec.stderr.is_empty(),
                                ),
                            )
                            .await?
                    }
                    Err(error) => return Err(error),
                };
                if process.terminal != exec.terminal {
                    return Err(RuntimeError::new(
                        ErrorCode::Conflict,
                        format!("runtime exec {exec_id} terminal mode changed during rehydration"),
                    )
                    .for_operation("containerd-shim-rehydrate"));
                }
                if let Some(state) = task.execs.get_mut(&exec_id) {
                    state.stage = ExecStage::Started;
                    state.record = Some(process);
                }
            }
        }
        metadata_from_task(&task).store()?;
        ShimCreateIntent::remove(&self.bundle)?;
        {
            let mut state = self.state.lock().await;
            if state.tasks.contains_key(expected_task_id) {
                return Err(RuntimeError::new(
                    ErrorCode::AlreadyExists,
                    format!("task {expected_task_id} is already hydrated"),
                )
                .for_operation("containerd-shim-rehydrate"));
            }
            state
                .tasks
                .insert(expected_task_id.to_string(), task.clone());
        }
        // Output replay starts as soon as a pump is created. Publish the
        // restored task first so its first delivered bytes can advance the
        // durable cursor instead of racing an absent in-memory task.
        let pumps = match self
            .start_restored_pumps(expected_task_id, &adapter, &task)
            .await
        {
            Ok(pumps) => pumps,
            Err(error) => {
                self.state.lock().await.tasks.remove(expected_task_id);
                return Err(error);
            }
        };
        let mut state = self.state.lock().await;
        if !state.tasks.contains_key(expected_task_id) {
            drop(state);
            for (_, pump) in pumps {
                pump.stop().await;
            }
            return Err(RuntimeError::new(
                ErrorCode::Internal,
                format!("task {expected_task_id} disappeared while restoring its I/O pumps"),
            )
            .for_operation("containerd-shim-rehydrate"));
        }
        state.pumps.extend(pumps);
        for ((task_id, _), pump) in &state.pumps {
            if task_id == expected_task_id && task.restore_state != RestoreState::PendingStart {
                pump.activate_stdin();
            }
        }
        let monitor_execs = state
            .tasks
            .get(expected_task_id)
            .map(|task| {
                task.execs
                    .iter()
                    .filter(|(_, exec)| exec.record.is_some() && exec.exit.is_none())
                    .map(|(exec_id, _)| exec_id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let monitor_init = state
            .tasks
            .get(expected_task_id)
            .is_some_and(|task| task.exit.is_none());
        drop(state);
        if monitor_init {
            self.ensure_exit_monitor(expected_task_id, None).await;
        }
        for exec_id in monitor_execs {
            self.ensure_exit_monitor(expected_task_id, Some(&exec_id))
                .await;
        }
        Ok(())
    }

    async fn start_restored_pumps(
        &self,
        task_id: &str,
        adapter: &RuntimeAdapter,
        task: &TaskState,
    ) -> Result<ProcessPumpSet, RuntimeError> {
        let mut pumps = Vec::new();
        if task.exit.is_none() {
            pumps.push((
                Self::pump_key(task_id, None),
                io::start_process_pumps(
                    adapter.clone(),
                    task.identity.clone(),
                    task.record.generation,
                    None,
                    ProcessIoEndpoints {
                        stdin: &task.stdin,
                        stdout: &task.stdout,
                        stderr: &task.stderr,
                        terminal: task.terminal,
                        await_start_activation: true,
                        read_stdin_at_activation: false,
                        stdin_sequence: task.stdin_sequence,
                        pending_stdin_write: task.pending_stdin_write.clone(),
                        stdin_close_state: task.stdin_close_state,
                        stdin_journal: Some(self.stdin_journal(task_id, None)),
                        output_cursor: task.output_cursor,
                        output_cursor_committer: Some(self.output_cursor_committer(task_id, None)),
                    },
                )?,
            ));
        }
        for (exec_id, exec) in &task.execs {
            if !matches!(exec.stage, ExecStage::Starting | ExecStage::Started)
                || exec.exit.is_some()
            {
                continue;
            }
            let pump = match exec.identity(exec_id).and_then(|exec_identity| {
                io::start_process_pumps(
                    adapter.clone(),
                    task.identity.clone(),
                    task.record.generation,
                    Some(exec_identity),
                    ProcessIoEndpoints {
                        stdin: &exec.stdin,
                        stdout: &exec.stdout,
                        stderr: &exec.stderr,
                        terminal: exec.terminal,
                        await_start_activation: true,
                        read_stdin_at_activation: false,
                        stdin_sequence: exec.stdin_sequence,
                        pending_stdin_write: exec.pending_stdin_write.clone(),
                        stdin_close_state: exec.stdin_close_state,
                        stdin_journal: Some(self.stdin_journal(task_id, Some(exec_id))),
                        output_cursor: exec.output_cursor,
                        output_cursor_committer: Some(
                            self.output_cursor_committer(task_id, Some(exec_id)),
                        ),
                    },
                )
            }) {
                Ok(pump) => pump,
                Err(error) => {
                    for (_, pump) in pumps {
                        pump.stop().await;
                    }
                    return Err(error);
                }
            };
            pumps.push((Self::pump_key(task_id, Some(exec_id)), pump));
        }
        Ok(pumps)
    }
}
