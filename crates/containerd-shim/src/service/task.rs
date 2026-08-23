use super::*;
use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use containerd_shim::{TtrpcContext, TtrpcResult};
use containerd_shim_protos::shim_async::Task;

use crate::contract::{OCI_LINUX_RESOURCES_TYPE_URL, OCI_PROCESS_TYPE_URL};

#[path = "task/start.rs"]
mod start;

#[async_trait]
impl Task for Service {
    async fn create(
        &self,
        _ctx: &TtrpcContext,
        req: api::CreateTaskRequest,
    ) -> TtrpcResult<api::CreateTaskResponse> {
        let task_id = req.id().to_string();
        let isolation = crate::options::decode(req.options.as_ref()).map_err(runtime_error)?;
        let bundle = tokio::fs::canonicalize(req.bundle())
            .await
            .map_err(|error| {
                ttrpc_invalid_argument(format!(
                    "failed to resolve containerd task bundle {}: {error}",
                    req.bundle()
                ))
            })?;
        if bundle != self.bundle {
            return Err(ttrpc_invalid_argument(format!(
                "containerd task bundle {} differs from shim bundle {}",
                bundle.display(),
                self.bundle.display()
            )));
        }
        {
            let mut state = self.state.lock().await;
            if let Some(error) = &state.restore_error {
                return Err(runtime_error(error.clone()));
            }
            if state.tasks.contains_key(&task_id) || !state.creating.insert(task_id.clone()) {
                return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                    ttrpc::Code::ALREADY_EXISTS,
                    format!("task {task_id} already exists"),
                )));
            }
        }
        if !req.checkpoint().is_empty() || !req.parent_checkpoint().is_empty() {
            self.state.lock().await.creating.remove(&task_id);
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::UNIMPLEMENTED,
                "containerd checkpoint restore is not yet implemented by A3S OCI Runtime"
                    .to_string(),
            )));
        }
        let identity = match self.identity(&task_id) {
            Ok(identity) => identity,
            Err(error) => {
                self.state.lock().await.creating.remove(&task_id);
                return Err(runtime_error(error));
            }
        };
        let rootfs_mounted = match self.mount_rootfs(&req).await {
            Ok(mounted) => mounted,
            Err(error) => {
                self.state.lock().await.creating.remove(&task_id);
                return Err(error);
            }
        };
        let io = adapter::process_io(
            req.terminal(),
            !req.stdin().is_empty(),
            !req.stdout().is_empty(),
            !req.stderr().is_empty(),
        );
        let create_intent = match ShimCreateIntent::new(NewShimCreateIntent {
            identity: identity.clone(),
            isolation: isolation.clone(),
            bundle: bundle.clone(),
            stdin: req.stdin().to_string(),
            stdout: req.stdout().to_string(),
            stderr: req.stderr().to_string(),
            terminal: req.terminal(),
            rootfs_mounted,
        }) {
            Ok(intent) => intent,
            Err(error) => {
                if rootfs_mounted {
                    let _ = Self::unmount_rootfs(Path::new(req.bundle()).join("rootfs")).await;
                }
                self.state.lock().await.creating.remove(&task_id);
                return Err(runtime_error(error));
            }
        };
        if let Err(error) = create_intent.store() {
            if rootfs_mounted {
                let _ = Self::unmount_rootfs(Path::new(req.bundle()).join("rootfs")).await;
            }
            self.state.lock().await.creating.remove(&task_id);
            return Err(runtime_error(error));
        }
        let adapter = match self.adapter().await {
            Ok(adapter) => adapter.with_isolation(isolation),
            Err(error) => {
                match ShimCreateIntent::remove(&bundle) {
                    Ok(()) if rootfs_mounted => {
                        let _ = Self::unmount_rootfs(Path::new(req.bundle()).join("rootfs")).await;
                    }
                    Ok(()) => {}
                    Err(cleanup_error) => {
                        log::error!(
                            "failed to remove pre-dispatch create intent; retaining the mounted rootfs for DeleteShim recovery: {cleanup_error}"
                        );
                    }
                }
                self.state.lock().await.creating.remove(&task_id);
                return Err(runtime_error(error));
            }
        };
        let record = match adapter.create(&identity, &bundle, io).await {
            Ok(record) => record,
            Err(error) => {
                if !error.retryable {
                    match ShimCreateIntent::remove(&bundle) {
                        Ok(()) if rootfs_mounted => {
                            let _ =
                                Self::unmount_rootfs(Path::new(req.bundle()).join("rootfs")).await;
                        }
                        Ok(()) => {}
                        Err(cleanup_error) => {
                            log::error!(
                                "failed to remove terminal create intent; retaining the mounted rootfs for DeleteShim recovery: {cleanup_error}"
                            );
                        }
                    }
                }
                self.state.lock().await.creating.remove(&task_id);
                return Err(runtime_error(error));
            }
        };
        let pid = record_pid(&record);
        let pumps = match io::start_process_pumps(
            adapter.clone(),
            identity.clone(),
            record.generation,
            None,
            ProcessIoEndpoints {
                stdin: req.stdin(),
                stdout: req.stdout(),
                stderr: req.stderr(),
                terminal: req.terminal(),
                await_start_activation: true,
                read_stdin_at_activation: true,
                stdin_sequence: 0,
                pending_stdin_write: None,
                stdin_close_state: StdinCloseState::Open,
                stdin_journal: Some(self.stdin_journal(&task_id, None)),
                output_cursor: 0,
                output_cursor_committer: Some(self.output_cursor_committer(&task_id, None)),
            },
        ) {
            Ok(pumps) => pumps,
            Err(error) => {
                self.rollback_created_task(
                    &adapter,
                    &identity,
                    record.generation,
                    &bundle,
                    rootfs_mounted,
                    "I/O pump startup failure",
                )
                .await;
                self.state.lock().await.creating.remove(&task_id);
                return Err(runtime_error(error));
            }
        };
        let task = TaskState {
            identity: identity.clone(),
            bundle: bundle.clone(),
            stdin: req.stdin().to_string(),
            stdout: req.stdout().to_string(),
            stderr: req.stderr().to_string(),
            terminal: req.terminal(),
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            resize_gate: Arc::new(Mutex::new(())),
            resize_sequence: 0,
            pending_resize: None,
            terminal_size: None,
            signal_gate: Arc::new(Mutex::new(())),
            signal_sequence: 0,
            pending_signal: None,
            output_cursor: 0,
            control_gate: Arc::new(Mutex::new(())),
            control_sequence: 0,
            pending_control: None,
            last_update_digest: None,
            rootfs_mounted,
            record: record.clone(),
            exit: None,
            exited_at: None,
            exec_sequence: 0,
            execs: BTreeMap::new(),
        };
        let mut state = self.state.lock().await;
        state.creating.remove(&task_id);
        if state.tasks.insert(task_id.clone(), task).is_some() {
            drop(state);
            pumps.stop().await;
            self.rollback_created_task(
                &adapter,
                &identity,
                record.generation,
                &bundle,
                rootfs_mounted,
                "duplicate task insertion",
            )
            .await;
            return Err(ttrpc_error(format!("task {task_id} already exists")));
        }
        state.pumps.insert(Self::pump_key(&task_id, None), pumps);
        drop(state);
        if let Err(error) = self.persist_task(&task_id).await {
            self.stop_task_pumps(&task_id).await;
            self.state.lock().await.tasks.remove(&task_id);
            self.rollback_created_task(
                &adapter,
                &identity,
                record.generation,
                &bundle,
                rootfs_mounted,
                "task metadata commit failure",
            )
            .await;
            return Err(error);
        }
        if let Err(error) = ShimCreateIntent::remove(&bundle) {
            log::warn!(
                "task {task_id} committed full shim metadata but retained its redundant create intent: {error}"
            );
        }
        self.publish_create(&req, pid).await;
        let mut response = api::CreateTaskResponse::new();
        response.set_pid(pid);
        Ok(response)
    }

    async fn start(
        &self,
        _ctx: &TtrpcContext,
        req: api::StartRequest,
    ) -> TtrpcResult<api::StartResponse> {
        self.start_task(req).await
    }

    async fn state(
        &self,
        _ctx: &TtrpcContext,
        req: api::StateRequest,
    ) -> TtrpcResult<api::StateResponse> {
        let task = self.refresh_task(req.id()).await?;
        let mut response = api::StateResponse::new();
        response.set_id(req.id().to_string());
        response.set_bundle(task.bundle.to_string_lossy().into_owned());
        if req.exec_id().is_empty() {
            response.set_stdin(task.stdin);
            response.set_stdout(task.stdout);
            response.set_stderr(task.stderr);
            response.set_terminal(task.terminal);
            response.set_pid(record_pid(&task.record));
            response.status = protobuf_task_status(&task.record, task.exit.is_some());
            if let Some(exit) = task.exit {
                response.set_exit_status(adapter::exit_code(&exit));
                response.set_exited_at(timestamp_from(task.exited_at.unwrap_or(SystemTime::now())));
            }
        } else {
            let exec = task
                .execs
                .get(req.exec_id())
                .ok_or_else(|| ttrpc_not_found(format!("unknown exec {}", req.exec_id())))?;
            response.set_exec_id(req.exec_id().to_string());
            response.set_stdin(exec.stdin.clone());
            response.set_stdout(exec.stdout.clone());
            response.set_stderr(exec.stderr.clone());
            response.set_terminal(exec.terminal);
            response.set_pid(
                exec.record
                    .as_ref()
                    .and_then(|record| record.pid)
                    .unwrap_or(0),
            );
            response.status = protobuf_exec_status(&task.record, exec);
            if let Some(exit) = &exec.exit {
                response.set_exit_status(adapter::exit_code(exit));
                response.set_exited_at(timestamp_from(exec.exited_at.unwrap_or(SystemTime::now())));
            }
        }
        Ok(response)
    }

    async fn exec(
        &self,
        _ctx: &TtrpcContext,
        req: api::ExecProcessRequest,
    ) -> TtrpcResult<api::Empty> {
        let task_id = req.id().to_string();
        let exec_id = req.exec_id().to_string();
        if exec_id.is_empty() {
            return Err(ttrpc_invalid_argument(
                "containerd exec ID must not be empty".to_string(),
            ));
        }
        if req.spec().type_url != OCI_PROCESS_TYPE_URL {
            return Err(ttrpc_invalid_argument(format!(
                "unsupported containerd exec process type {}; expected {OCI_PROCESS_TYPE_URL}",
                req.spec().type_url
            )));
        }
        let process = serde_json::from_slice(&req.spec().value).map_err(|error| {
            ttrpc_invalid_argument(format!("invalid OCI exec process: {error}"))
        })?;
        let process = a3s_oci_sdk::process_serde::decode(process).map_err(|error| {
            ttrpc_invalid_argument(format!("invalid OCI exec process: {error}"))
        })?;
        let mut exec = ExecState {
            incarnation: 0,
            process,
            stdin: req.stdin().to_string(),
            stdout: req.stdout().to_string(),
            stderr: req.stderr().to_string(),
            terminal: req.terminal(),
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            resize_gate: Arc::new(Mutex::new(())),
            resize_sequence: 0,
            pending_resize: None,
            terminal_size: None,
            signal_gate: Arc::new(Mutex::new(())),
            signal_sequence: 0,
            pending_signal: None,
            output_cursor: 0,
            stage: ExecStage::Added,
            record: None,
            exit: None,
            exited_at: None,
        };
        let _metadata_guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| ttrpc_error(format!("unknown task {task_id}")))?;
        if task.execs.contains_key(&exec_id) {
            return Err(ttrpc_already_exists(format!(
                "exec {exec_id} already exists"
            )));
        }
        let incarnation = task.exec_sequence.checked_add(1).ok_or_else(|| {
            runtime_error(
                RuntimeError::new(
                    ErrorCode::ResourceExhausted,
                    format!("containerd task {task_id} exhausted its exec incarnation sequence"),
                )
                .for_operation("containerd-exec-allocate"),
            )
        })?;
        exec.incarnation = incarnation;
        let mut persisted = task.clone();
        persisted.exec_sequence = incarnation;
        persisted.execs.insert(exec_id.clone(), exec.clone());
        metadata_from_task(&persisted)
            .store()
            .map_err(runtime_error)?;
        task.exec_sequence = incarnation;
        task.execs.insert(exec_id.clone(), exec);
        drop(state);
        self.publish_exec_added(&task_id, &exec_id).await;
        Ok(api::Empty::new())
    }

    async fn wait(
        &self,
        _ctx: &TtrpcContext,
        req: api::WaitRequest,
    ) -> TtrpcResult<api::WaitResponse> {
        let task_id = req.id().to_string();
        let exec_id = req.exec_id().to_string();
        let exec_id = (!exec_id.is_empty()).then_some(exec_id);
        let (exit, _pid, exited_at) = self
            .wait_for_recorded_exit(&task_id, exec_id.as_deref())
            .await?;
        let mut response = api::WaitResponse::new();
        response.set_exit_status(adapter::exit_code(&exit));
        response.set_exited_at(timestamp_from(exited_at));
        Ok(response)
    }

    async fn kill(&self, _ctx: &TtrpcContext, req: api::KillRequest) -> TtrpcResult<api::Empty> {
        let task = self.task_snapshot(req.id()).await?;
        let signal = i32::try_from(req.signal()).map_err(|_| {
            ttrpc_invalid_argument(format!(
                "containerd signal {} exceeds the runtime signal range",
                req.signal()
            ))
        })?;
        if signal == 0 {
            return Err(ttrpc_invalid_argument(
                "containerd signal must be positive; signal 0 is not a lifecycle mutation"
                    .to_string(),
            ));
        }
        let exec_id = (!req.exec_id().is_empty()).then_some(req.exec_id());
        let signal_gate = if let Some(exec_id) = exec_id {
            task.execs
                .get(exec_id)
                .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?
                .signal_gate
                .clone()
        } else {
            task.signal_gate.clone()
        };
        let all = exec_id.is_none() && req.all();
        let _signal_guard = signal_gate.lock().await;
        loop {
            let prepared = self
                .prepare_signal(req.id(), exec_id, &signal_gate, signal, all)
                .await?;
            let requested_operation =
                prepared.operation.signal().get() == signal && prepared.operation.all() == all;
            let adapter = match self.adapter().await {
                Ok(adapter) => adapter,
                Err(error) => {
                    self.finish_signal_error(
                        req.id(),
                        exec_id,
                        &signal_gate,
                        &prepared.operation,
                        &error,
                    )
                    .await?;
                    return Err(runtime_error(error));
                }
            };
            match signal::dispatch(&adapter, &prepared.task, exec_id, &prepared.operation).await {
                Ok(record) => {
                    self.complete_signal(
                        req.id(),
                        exec_id,
                        &signal_gate,
                        &prepared.operation,
                        record,
                    )
                    .await?;
                }
                Err(error) => {
                    self.finish_signal_error(
                        req.id(),
                        exec_id,
                        &signal_gate,
                        &prepared.operation,
                        &error,
                    )
                    .await?;
                    return Err(runtime_error(error));
                }
            }
            if requested_operation {
                return Ok(api::Empty::new());
            }
        }
    }

    async fn pause(&self, _ctx: &TtrpcContext, req: api::PauseRequest) -> TtrpcResult<api::Empty> {
        let control_gate = self.task_snapshot(req.id()).await?.control_gate;
        let _control_guard = control_gate.lock().await;
        let Some(prepared) = self
            .prepare_control(
                req.id(),
                &control_gate,
                ControlOperationKind::Pause,
                None,
                None,
            )
            .await?
        else {
            return Ok(api::Empty::new());
        };
        let adapter = match self.adapter().await {
            Ok(adapter) => adapter,
            Err(error) => {
                self.finish_control_error(req.id(), &prepared.operation, &error)
                    .await?;
                return Err(runtime_error(error));
            }
        };
        let record = match adapter
            .pause(
                &prepared.task.identity,
                prepared.task.record.generation,
                prepared.operation.sequence(),
            )
            .await
        {
            Ok(record) => record,
            Err(error) => {
                self.finish_control_error(req.id(), &prepared.operation, &error)
                    .await?;
                return Err(runtime_error(error));
            }
        };
        self.complete_control(req.id(), &prepared.operation, record)
            .await?;
        self.publish_paused(req.id()).await;
        Ok(api::Empty::new())
    }

    async fn resume(
        &self,
        _ctx: &TtrpcContext,
        req: api::ResumeRequest,
    ) -> TtrpcResult<api::Empty> {
        let control_gate = self.task_snapshot(req.id()).await?.control_gate;
        let _control_guard = control_gate.lock().await;
        let Some(prepared) = self
            .prepare_control(
                req.id(),
                &control_gate,
                ControlOperationKind::Resume,
                None,
                None,
            )
            .await?
        else {
            return Ok(api::Empty::new());
        };
        let adapter = match self.adapter().await {
            Ok(adapter) => adapter,
            Err(error) => {
                self.finish_control_error(req.id(), &prepared.operation, &error)
                    .await?;
                return Err(runtime_error(error));
            }
        };
        let record = match adapter
            .resume(
                &prepared.task.identity,
                prepared.task.record.generation,
                prepared.operation.sequence(),
            )
            .await
        {
            Ok(record) => record,
            Err(error) => {
                self.finish_control_error(req.id(), &prepared.operation, &error)
                    .await?;
                return Err(runtime_error(error));
            }
        };
        self.complete_control(req.id(), &prepared.operation, record)
            .await?;
        self.publish_resumed(req.id()).await;
        Ok(api::Empty::new())
    }

    async fn checkpoint(
        &self,
        _ctx: &TtrpcContext,
        _req: api::CheckpointTaskRequest,
    ) -> TtrpcResult<api::Empty> {
        Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
            ttrpc::Code::UNIMPLEMENTED,
            "checkpoint/restore is not yet implemented by A3S OCI Runtime".to_string(),
        )))
    }

    async fn update(
        &self,
        _ctx: &TtrpcContext,
        req: api::UpdateTaskRequest,
    ) -> TtrpcResult<api::Empty> {
        if !req.annotations().is_empty() {
            return Err(ttrpc_invalid_argument(
                "containerd update annotations are not part of the A3S OCI resource contract"
                    .to_string(),
            ));
        }
        let resources_any = req.resources.as_ref().ok_or_else(|| {
            ttrpc_invalid_argument("containerd update omitted LinuxResources".to_string())
        })?;
        if resources_any.type_url != OCI_LINUX_RESOURCES_TYPE_URL {
            return Err(ttrpc_invalid_argument(format!(
                "unsupported containerd resource type {}; expected {OCI_LINUX_RESOURCES_TYPE_URL}",
                resources_any.type_url
            )));
        }
        let resources: LinuxResources =
            serde_json::from_slice(&resources_any.value).map_err(|error| {
                ttrpc_invalid_argument(format!("invalid OCI LinuxResources JSON: {error}"))
            })?;
        let digest = control::update_request_digest(&resources).map_err(runtime_error)?;
        let control_gate = self.task_snapshot(req.id()).await?.control_gate;
        let _control_guard = control_gate.lock().await;
        let Some(prepared) = self
            .prepare_control(
                req.id(),
                &control_gate,
                ControlOperationKind::Update,
                Some(digest),
                Some(resources),
            )
            .await?
        else {
            return Ok(api::Empty::new());
        };
        let adapter = match self.adapter().await {
            Ok(adapter) => adapter,
            Err(error) => {
                self.finish_control_error(req.id(), &prepared.operation, &error)
                    .await?;
                return Err(runtime_error(error));
            }
        };
        let record = match adapter
            .update(
                &prepared.task.identity,
                prepared.task.record.generation,
                prepared.operation.sequence(),
                prepared.operation.resources().cloned().ok_or_else(|| {
                    runtime_error(
                        RuntimeError::new(
                            ErrorCode::FailedPrecondition,
                            "prepared containerd Update omitted its persisted Linux resources",
                        )
                        .for_operation("containerd-update-dispatch"),
                    )
                })?,
            )
            .await
        {
            Ok(record) => record,
            Err(error) => {
                self.finish_control_error(req.id(), &prepared.operation, &error)
                    .await?;
                return Err(runtime_error(error));
            }
        };
        self.complete_control(req.id(), &prepared.operation, record)
            .await?;
        Ok(api::Empty::new())
    }

    async fn delete(
        &self,
        _ctx: &TtrpcContext,
        req: api::DeleteRequest,
    ) -> TtrpcResult<api::DeleteResponse> {
        let task_id = req.id().to_string();
        let exec_id = req.exec_id().to_string();
        if !exec_id.is_empty() {
            let _metadata_guard = self.metadata_gate.lock().await;
            let mut state = self.state.lock().await;
            let task = state
                .tasks
                .get(&task_id)
                .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
            let Some(exec) = task.execs.get(&exec_id) else {
                return Err(ttrpc_not_found(format!("unknown exec {exec_id}")));
            };
            if exec.record.is_some() && exec.exit.is_none() {
                return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                    ttrpc::Code::FAILED_PRECONDITION,
                    format!("cannot delete running exec {exec_id}"),
                )));
            }
            let exec = exec.clone();
            let mut persisted = task.clone();
            persisted.execs.remove(&exec_id);
            metadata_from_task(&persisted)
                .store()
                .map_err(runtime_error)?;
            let mut response = api::DeleteResponse::new();
            let pid = exec
                .record
                .as_ref()
                .and_then(|record| record.pid)
                .unwrap_or(0);
            let code = exec.exit.as_ref().map_or(0, adapter::exit_code);
            let exited_at = exec.exited_at.unwrap_or(SystemTime::now());
            response.set_pid(pid);
            response.set_exit_status(code);
            state
                .tasks
                .get_mut(&task_id)
                .ok_or_else(|| {
                    ttrpc_error(format!("task {task_id} disappeared during exec delete"))
                })?
                .execs
                .remove(&exec_id);
            let pump = state
                .pumps
                .remove(&Self::pump_key(&task_id, Some(&exec_id)));
            state
                .wait_errors
                .remove(&Self::pump_key(&task_id, Some(&exec_id)));
            drop(state);
            if let Some(pump) = pump {
                pump.stop().await;
            }
            self.stop_process_monitor(&task_id, Some(&exec_id)).await;
            self.publish_delete(&task_id, Some(&exec_id), pid, code, exited_at)
                .await;
            response.set_exited_at(timestamp_from(exited_at));
            return Ok(response);
        }
        let state = self.state.lock().await;
        let task = state
            .tasks
            .get(&task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        let snapshot = task.clone();
        drop(state);
        let adapter = self.adapter().await.map_err(runtime_error)?;
        // Stop all FIFO readers before reserving delete so no new stdin/EOF
        // mutation can race the runtime's active-process gate. Already-issued
        // mutations remain cancellation-safe and delete retries the same
        // durable identity until those claims finish or the bounded deadline
        // expires.
        self.stop_task_pumps(&task_id).await;
        adapter
            .delete(&snapshot.identity, snapshot.record.generation, false)
            .await
            .map_err(runtime_error)?;
        self.stop_task_monitors(&task_id).await;
        ShimCreateIntent::remove(&snapshot.bundle).map_err(runtime_error)?;
        if snapshot.rootfs_mounted {
            Self::unmount_rootfs(snapshot.bundle.join("rootfs")).await?;
        }
        ShimMetadata::remove(&snapshot.bundle).map_err(runtime_error)?;
        self.state.lock().await.tasks.remove(&task_id);
        let mut response = api::DeleteResponse::new();
        let pid = record_pid(&snapshot.record);
        let code = snapshot.exit.as_ref().map_or(0, adapter::exit_code);
        let exited_at = snapshot.exited_at.unwrap_or(SystemTime::now());
        response.set_pid(pid);
        response.set_exit_status(code);
        response.set_exited_at(timestamp_from(exited_at));
        self.publish_delete(&task_id, None, pid, code, exited_at)
            .await;
        Ok(response)
    }

    async fn pids(
        &self,
        _ctx: &TtrpcContext,
        req: api::PidsRequest,
    ) -> TtrpcResult<api::PidsResponse> {
        let task = self.task_snapshot(req.id()).await?;
        let adapter = self.adapter().await.map_err(runtime_error)?;
        let processes = adapter
            .processes(&task.identity, task.record.generation)
            .await
            .map_err(runtime_error)?;
        let mut response = api::PidsResponse::new();
        response.set_processes(
            processes
                .into_iter()
                .filter_map(|process| process.pid)
                .map(|pid| {
                    let mut info = containerd_shim_protos::types::task::ProcessInfo::new();
                    info.set_pid(pid);
                    info
                })
                .collect(),
        );
        Ok(response)
    }

    async fn resize_pty(
        &self,
        _ctx: &TtrpcContext,
        req: api::ResizePtyRequest,
    ) -> TtrpcResult<api::Empty> {
        let task = self.task_snapshot(req.id()).await?;
        let exec_id = (!req.exec_id().is_empty()).then_some(req.exec_id());
        let resize_gate = if let Some(exec_id) = exec_id {
            task.execs
                .get(exec_id)
                .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?
                .resize_gate
                .clone()
        } else {
            task.resize_gate.clone()
        };
        let Some(size) = containerd_terminal_size(req.width(), req.height())? else {
            return Ok(api::Empty::new());
        };
        let _resize_guard = resize_gate.lock().await;
        loop {
            let Some(prepared) = self
                .prepare_resize(req.id(), exec_id, &resize_gate, size)
                .await?
            else {
                return Ok(api::Empty::new());
            };
            let requested_operation = prepared.operation.size() == size;
            let adapter = match self.adapter().await {
                Ok(adapter) => adapter,
                Err(error) => {
                    self.finish_resize_error(
                        req.id(),
                        exec_id,
                        &resize_gate,
                        &prepared.operation,
                        &error,
                    )
                    .await?;
                    return Err(runtime_error(error));
                }
            };
            match resize::dispatch(&adapter, &prepared.task, exec_id, &prepared.operation).await {
                Ok(()) => {
                    self.complete_resize(
                        req.id(),
                        exec_id,
                        &resize_gate,
                        &prepared.operation,
                        true,
                    )
                    .await?;
                }
                Err(error) => {
                    self.finish_resize_error(
                        req.id(),
                        exec_id,
                        &resize_gate,
                        &prepared.operation,
                        &error,
                    )
                    .await?;
                    return Err(runtime_error(error));
                }
            }
            if requested_operation {
                return Ok(api::Empty::new());
            }
        }
    }

    async fn close_io(
        &self,
        _ctx: &TtrpcContext,
        req: api::CloseIORequest,
    ) -> TtrpcResult<api::Empty> {
        if req.stdin() {
            // containerd invokes CloseIO synchronously before it can close its
            // FIFO writer. The shim may still have buffered FIFO bytes waiting
            // on SDK backpressure. The stdin pump owns both ordered writes and
            // the final EOF; waiting for its durable result prevents CloseIO
            // from overtaking those writes and silently truncating stdin.
            self.task_snapshot(req.id()).await?;
            self.wait_for_stdin_drain(
                req.id(),
                (!req.exec_id().is_empty()).then_some(req.exec_id()),
            )
            .await?;
        }
        Ok(api::Empty::new())
    }

    async fn stats(
        &self,
        _ctx: &TtrpcContext,
        req: api::StatsRequest,
    ) -> TtrpcResult<api::StatsResponse> {
        let task = self.task_snapshot(req.id()).await?;
        let adapter = self.adapter().await.map_err(runtime_error)?;
        let stats = adapter
            .stats(&task.identity, task.record.generation)
            .await
            .map_err(runtime_error)?;
        let any = crate::stats::encode(&stats).map_err(runtime_error)?;
        let mut response = api::StatsResponse::new();
        response.set_stats(any);
        Ok(response)
    }

    async fn connect(
        &self,
        _ctx: &TtrpcContext,
        req: api::ConnectRequest,
    ) -> TtrpcResult<api::ConnectResponse> {
        let mut response = api::ConnectResponse::new();
        response.set_shim_pid(std::process::id());
        response.set_version(env!("CARGO_PKG_VERSION").to_string());
        if !req.id().is_empty() {
            let task = self.task_snapshot(req.id()).await?;
            response.set_task_pid(record_pid(&task.record));
        }
        Ok(response)
    }

    async fn shutdown(
        &self,
        _ctx: &TtrpcContext,
        req: api::ShutdownRequest,
    ) -> TtrpcResult<api::Empty> {
        if !req.now() {
            let state = self.state.lock().await;
            if !state.tasks.is_empty() || !state.creating.is_empty() {
                return Ok(api::Empty::new());
            }
        }
        self.stop_all_monitors().await;
        self.stop_all_pumps().await;
        self.exit.signal();
        Ok(api::Empty::new())
    }
}

fn containerd_terminal_size(width: u32, height: u32) -> TtrpcResult<Option<TerminalSize>> {
    if width == 0 && height == 0 {
        return Ok(None);
    }
    if width == 0 || height == 0 {
        return Err(ttrpc_invalid_argument(
            "terminal width and height must either both be zero or both be positive".to_string(),
        ));
    }
    let width = u16::try_from(width)
        .map_err(|_| ttrpc_invalid_argument("terminal width exceeds u16".to_string()))?;
    let height = u16::try_from(height)
        .map_err(|_| ttrpc_invalid_argument("terminal height exceeds u16".to_string()))?;
    Ok(Some(TerminalSize { width, height }))
}

#[cfg(test)]
mod terminal_size_tests {
    use super::containerd_terminal_size;

    #[test]
    fn zero_terminal_size_is_a_containerd_noop() {
        assert_eq!(
            containerd_terminal_size(0, 0).expect("zero-size no-op"),
            None
        );
    }

    #[test]
    fn terminal_size_requires_two_bounded_positive_dimensions() {
        assert!(containerd_terminal_size(80, 0).is_err());
        assert!(containerd_terminal_size(0, 24).is_err());
        assert!(containerd_terminal_size(u32::from(u16::MAX) + 1, 24).is_err());
        let size = containerd_terminal_size(120, 40)
            .expect("valid terminal size")
            .expect("terminal resize");
        assert_eq!((size.width, size.height), (120, 40));
    }
}
