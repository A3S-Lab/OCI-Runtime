use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerRecord, Error as RuntimeError, ErrorCode, ExitStatus, IsolationRequest, ProcessRecord,
    TerminalSize,
};
use async_trait::async_trait;
use containerd_shim::asynchronous::{spawn, ExitSignal, Shim};
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::{Config, Error, Flags, StartOpts, TtrpcResult};
use containerd_shim_protos::{api, protobuf, ttrpc};
use tokio::sync::{Mutex, Notify};

use crate::adapter::{self, RuntimeAdapter, TaskIdentity};
use crate::io::{self, ProcessIoEndpoints, ProcessPumps};
use crate::metadata::{
    ControlOperationKind, ExecMetadata, ExecStage, NewShimCreateIntent, NewShimMetadata,
    PendingControlOperation, PendingStdinWrite, ShimCreateIntent, ShimMetadata,
};

mod control;
mod task;

#[cfg(test)]
mod tests;

#[cfg(unix)]
const DEFAULT_ENDPOINT: &str = "/run/a3s-oci/runtime.sock";
#[cfg(windows)]
const DEFAULT_ENDPOINT: &str = r"\\.\pipe\a3s-oci-runtime";
const DELETE_SHIM_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct TaskState {
    identity: TaskIdentity,
    bundle: PathBuf,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    stdin_sequence: u64,
    pending_stdin_write: Option<PendingStdinWrite>,
    output_cursor: u64,
    control_gate: Arc<Mutex<()>>,
    control_sequence: u64,
    pending_control: Option<PendingControlOperation>,
    last_update_digest: Option<String>,
    rootfs_mounted: bool,
    record: ContainerRecord,
    exit: Option<ExitStatus>,
    exited_at: Option<SystemTime>,
    execs: BTreeMap<String, ExecState>,
}

#[derive(Debug, Clone)]
struct ExecState {
    process: Process,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    stdin_sequence: u64,
    pending_stdin_write: Option<PendingStdinWrite>,
    output_cursor: u64,
    stage: ExecStage,
    record: Option<ProcessRecord>,
    exit: Option<ExitStatus>,
    exited_at: Option<SystemTime>,
}

#[derive(Default)]
struct ServiceState {
    tasks: BTreeMap<String, TaskState>,
    creating: BTreeSet<String>,
    pumps: BTreeMap<(String, String), ProcessPumps>,
    wait_errors: BTreeMap<(String, String), ttrpc::Error>,
    restore_error: Option<RuntimeError>,
}

struct ExitMonitor {
    owner: Arc<()>,
    abort: tokio::task::AbortHandle,
}

#[derive(Clone)]
pub(crate) struct Service {
    namespace: String,
    task_id: String,
    endpoint: String,
    bundle: PathBuf,
    exit: Arc<ExitSignal>,
    state: Arc<Mutex<ServiceState>>,
    metadata_gate: Arc<Mutex<()>>,
    monitors: Arc<Mutex<BTreeMap<(String, String), ExitMonitor>>>,
    exit_notify: Arc<Notify>,
    publisher: Option<Arc<RemotePublisher>>,
    #[cfg(test)]
    test_adapter: Arc<Mutex<Option<RuntimeAdapter>>>,
}

struct DurableOutputCursor {
    state: Weak<Mutex<ServiceState>>,
    metadata_gate: Weak<Mutex<()>>,
    task_id: String,
    exec_id: Option<String>,
}

struct DurableStdinJournal {
    state: Weak<Mutex<ServiceState>>,
    metadata_gate: Weak<Mutex<()>>,
    task_id: String,
    exec_id: Option<String>,
}

#[async_trait]
impl io::OutputCursorCommitter for DurableOutputCursor {
    async fn commit(&self, cursor: u64) -> Result<(), RuntimeError> {
        let state = self.state.upgrade().ok_or_else(|| {
            RuntimeError::new(
                ErrorCode::Unavailable,
                "containerd shim state closed before output cursor commit",
            )
            .for_operation("containerd-output-cursor")
            .retryable(true)
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            RuntimeError::new(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before output cursor commit",
            )
            .for_operation("containerd-output-cursor")
            .retryable(true)
        })?;
        let _guard = metadata_gate.lock().await;
        let (task_snapshot, previous) = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                RuntimeError::new(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before output cursor commit",
                        self.task_id
                    ),
                )
                .for_operation("containerd-output-cursor")
            })?;
            let current = if let Some(exec_id) = &self.exec_id {
                &mut task
                    .execs
                    .get_mut(exec_id)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            ErrorCode::NotFound,
                            format!(
                                "containerd exec {exec_id} disappeared before output cursor commit"
                            ),
                        )
                        .for_operation("containerd-output-cursor")
                    })?
                    .output_cursor
            } else {
                &mut task.output_cursor
            };
            if cursor <= *current {
                return Ok(());
            }
            let previous = *current;
            *current = cursor;
            (task.clone(), previous)
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                let current = if let Some(exec_id) = &self.exec_id {
                    task.execs
                        .get_mut(exec_id)
                        .map(|exec| &mut exec.output_cursor)
                } else {
                    Some(&mut task.output_cursor)
                };
                if let Some(current) = current {
                    if *current == cursor {
                        *current = previous;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

#[async_trait]
impl io::StdinJournal for DurableStdinJournal {
    async fn prepare(&self, sequence: u64, data: Vec<u8>) -> Result<(), RuntimeError> {
        let pending = PendingStdinWrite::new(sequence, data)?;
        let state = self.state.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim state closed before stdin prepare",
                true,
            )
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before stdin prepare",
                true,
            )
        })?;
        let _guard = metadata_gate.lock().await;
        let task_snapshot = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before stdin prepare",
                        self.task_id
                    ),
                    false,
                )
            })?;
            let (completed, current) = stdin_state_mut(task, self.exec_id.as_deref())?;
            if let Some(current) = current.as_ref() {
                if current == &pending {
                    return Ok(());
                }
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    format!(
                        "containerd stdin sequence {} is already pending with different data",
                        current.sequence()
                    ),
                    false,
                ));
            }
            if completed.checked_add(1) != Some(sequence) {
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    format!(
                        "containerd stdin sequence {sequence} does not follow completed sequence {}",
                        *completed
                    ),
                    false,
                ));
            }
            *current = Some(pending.clone());
            task.clone()
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                if let Ok((_, current)) = stdin_state_mut(task, self.exec_id.as_deref()) {
                    if current.as_ref() == Some(&pending) {
                        *current = None;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }

    async fn commit(&self, sequence: u64) -> Result<(), RuntimeError> {
        let state = self.state.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim state closed before stdin commit",
                true,
            )
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before stdin commit",
                true,
            )
        })?;
        let _guard = metadata_gate.lock().await;
        let (task_snapshot, previous_sequence, previous_pending) = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before stdin commit",
                        self.task_id
                    ),
                    false,
                )
            })?;
            let (completed, current) = stdin_state_mut(task, self.exec_id.as_deref())?;
            if *completed == sequence && current.is_none() {
                return Ok(());
            }
            let pending = current.as_ref().ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::Conflict,
                    format!("containerd stdin sequence {sequence} was not prepared"),
                    false,
                )
            })?;
            if pending.sequence() != sequence || completed.checked_add(1) != Some(sequence) {
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    format!(
                        "containerd stdin commit sequence {sequence} does not match completed sequence {} and pending sequence {}",
                        *completed,
                        pending.sequence()
                    ),
                    false,
                ));
            }
            let previous_sequence = *completed;
            let previous_pending = current.take();
            *completed = sequence;
            (task.clone(), previous_sequence, previous_pending)
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                if let Ok((completed, current)) = stdin_state_mut(task, self.exec_id.as_deref()) {
                    if *completed == sequence && current.is_none() {
                        *completed = previous_sequence;
                        *current = previous_pending;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

fn stdin_state_mut<'a>(
    task: &'a mut TaskState,
    exec_id: Option<&str>,
) -> Result<(&'a mut u64, &'a mut Option<PendingStdinWrite>), RuntimeError> {
    if let Some(exec_id) = exec_id {
        let exec = task.execs.get_mut(exec_id).ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::NotFound,
                format!("containerd exec {exec_id} disappeared before stdin journal update"),
                false,
            )
        })?;
        Ok((&mut exec.stdin_sequence, &mut exec.pending_stdin_write))
    } else {
        Ok((&mut task.stdin_sequence, &mut task.pending_stdin_write))
    }
}

fn stdin_journal_error(
    code: ErrorCode,
    message: impl Into<String>,
    retryable: bool,
) -> RuntimeError {
    RuntimeError::new(code, message)
        .for_operation("containerd-stdin-journal")
        .retryable(retryable)
}

impl Service {
    fn endpoint_from_environment() -> String {
        std::env::var("A3S_OCI_RUNTIME_ENDPOINT")
            .or_else(|_| std::env::var("A3S_OCI_RUNTIME_SOCKET"))
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
    }

    async fn adapter(&self) -> Result<RuntimeAdapter, RuntimeError> {
        #[cfg(test)]
        if let Some(adapter) = self.test_adapter.lock().await.clone() {
            return Ok(adapter);
        }
        RuntimeAdapter::connect(&self.endpoint, IsolationRequest::SharedHostKernel).await
    }

    fn metadata_path(&self) -> PathBuf {
        ShimMetadata::path(&self.bundle)
    }

    fn output_cursor_committer(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
    ) -> Arc<dyn io::OutputCursorCommitter> {
        Arc::new(DurableOutputCursor {
            state: Arc::downgrade(&self.state),
            metadata_gate: Arc::downgrade(&self.metadata_gate),
            task_id: task_id.to_string(),
            exec_id: exec_id.map(str::to_string),
        })
    }

    fn stdin_journal(&self, task_id: &str, exec_id: Option<&str>) -> Arc<dyn io::StdinJournal> {
        Arc::new(DurableStdinJournal {
            state: Arc::downgrade(&self.state),
            metadata_gate: Arc::downgrade(&self.metadata_gate),
            task_id: task_id.to_string(),
            exec_id: exec_id.map(str::to_string),
        })
    }

    async fn rollback_created_task(
        &self,
        adapter: &RuntimeAdapter,
        identity: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        bundle: &Path,
        rootfs_mounted: bool,
        context: &str,
    ) {
        if let Err(error) = adapter.delete(identity, generation, true).await {
            log::error!(
                "failed to force-delete runtime generation during {context}; retaining create intent for DeleteShim recovery: {error}"
            );
            return;
        }
        if let Err(error) = ShimCreateIntent::remove(bundle) {
            log::error!(
                "failed to remove create intent after runtime rollback during {context}: {error}"
            );
            return;
        }
        if rootfs_mounted {
            if let Err(error) = Self::unmount_rootfs(bundle.join("rootfs")).await {
                log::error!(
                    "failed to unmount rootfs after runtime rollback during {context}: {error}"
                );
            }
        }
    }

    async fn persist_task(&self, task_id: &str) -> TtrpcResult<()> {
        let _guard = self.metadata_gate.lock().await;
        let task = self.task_snapshot_unchecked(task_id).await?;
        metadata_from_task(&task).store().map_err(runtime_error)
    }

    async fn task_snapshot_unchecked(&self, task_id: &str) -> TtrpcResult<TaskState> {
        self.state
            .lock()
            .await
            .tasks
            .get(task_id)
            .cloned()
            .ok_or_else(|| ttrpc_not_found(format!("unknown containerd task {task_id}")))
    }

    async fn restore_task(&self, expected_task_id: &str) -> Result<(), RuntimeError> {
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
        let mut task = TaskState {
            identity: identity.clone(),
            bundle: metadata.bundle().to_path_buf(),
            stdin: metadata.stdin().to_string(),
            stdout: metadata.stdout().to_string(),
            stderr: metadata.stderr().to_string(),
            terminal: metadata.terminal(),
            stdin_sequence: metadata.stdin_sequence(),
            pending_stdin_write: metadata.pending_stdin_write().cloned(),
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
            execs: BTreeMap::new(),
        };
        for exec in metadata.execs() {
            task.execs.insert(
                exec.exec_id.clone(),
                ExecState {
                    process: exec.process.clone(),
                    stdin: exec.stdin.clone(),
                    stdout: exec.stdout.clone(),
                    stderr: exec.stderr.clone(),
                    terminal: exec.terminal,
                    stdin_sequence: exec.stdin_sequence,
                    pending_stdin_write: exec.pending_stdin_write.clone(),
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
        let mut pumps = Vec::new();
        if task.exit.is_none() {
            pumps.push((
                Self::pump_key(expected_task_id, None),
                io::start_process_pumps(
                    adapter.clone(),
                    identity.clone(),
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
                        stdin_journal: Some(self.stdin_journal(expected_task_id, None)),
                        output_cursor: task.output_cursor,
                        output_cursor_committer: Some(
                            self.output_cursor_committer(expected_task_id, None),
                        ),
                    },
                )?,
            ));
        }
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
                let process = match adapter
                    .process(&identity, task.record.generation, &exec_id)
                    .await
                {
                    Ok(process) => process,
                    Err(error) if error.code == ErrorCode::NotFound => {
                        adapter
                            .exec(
                                &identity,
                                task.record.generation,
                                &exec_id,
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
                let pump_exec = task.execs.get(&exec_id).cloned().ok_or_else(|| {
                    RuntimeError::new(
                        ErrorCode::Internal,
                        format!("exec {exec_id} disappeared before I/O rehydration"),
                    )
                    .for_operation("containerd-shim-rehydrate")
                })?;
                match io::start_process_pumps(
                    adapter.clone(),
                    identity.clone(),
                    task.record.generation,
                    Some(exec_id.clone()),
                    ProcessIoEndpoints {
                        stdin: &pump_exec.stdin,
                        stdout: &pump_exec.stdout,
                        stderr: &pump_exec.stderr,
                        terminal: pump_exec.terminal,
                        await_start_activation: true,
                        read_stdin_at_activation: false,
                        stdin_sequence: pump_exec.stdin_sequence,
                        pending_stdin_write: pump_exec.pending_stdin_write.clone(),
                        stdin_journal: Some(self.stdin_journal(expected_task_id, Some(&exec_id))),
                        output_cursor: pump_exec.output_cursor,
                        output_cursor_committer: Some(
                            self.output_cursor_committer(expected_task_id, Some(&exec_id)),
                        ),
                    },
                ) {
                    Ok(pump) => {
                        pumps.push((Self::pump_key(expected_task_id, Some(&exec_id)), pump))
                    }
                    Err(error) => {
                        for (_, pump) in pumps {
                            pump.stop().await;
                        }
                        return Err(error);
                    }
                }
            }
        }
        metadata_from_task(&task).store()?;
        ShimCreateIntent::remove(&self.bundle)?;
        let mut state = self.state.lock().await;
        if state.tasks.contains_key(expected_task_id) {
            drop(state);
            for (_, pump) in pumps {
                pump.stop().await;
            }
            return Err(RuntimeError::new(
                ErrorCode::AlreadyExists,
                format!("task {expected_task_id} is already hydrated"),
            )
            .for_operation("containerd-shim-rehydrate"));
        }
        state.tasks.insert(expected_task_id.to_string(), task);
        state.pumps.extend(pumps);
        for ((task_id, _), pump) in &state.pumps {
            if task_id == expected_task_id {
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

    fn identity(&self, task_id: &str) -> Result<TaskIdentity, RuntimeError> {
        let incarnation = ShimMetadata::load_or_create_incarnation(&self.bundle)?;
        TaskIdentity::with_incarnation(self.namespace.clone(), task_id.to_string(), incarnation)
    }

    async fn publish(&self, topic: &str, event: Box<dyn protobuf::MessageDyn>) {
        if let Some(publisher) = &self.publisher {
            if let Err(error) = publisher
                .publish(
                    ttrpc::context::Context::default(),
                    topic,
                    &self.namespace,
                    event,
                )
                .await
            {
                log::warn!("failed to publish containerd event {topic}: {error}");
            }
        }
    }

    async fn publish_create(&self, req: &api::CreateTaskRequest, pid: u32) {
        let mut io = containerd_shim_protos::events::task::TaskIO::new();
        io.set_stdin(req.stdin().to_string());
        io.set_stdout(req.stdout().to_string());
        io.set_stderr(req.stderr().to_string());
        io.set_terminal(req.terminal());
        let mut event = containerd_shim_protos::events::task::TaskCreate::new();
        event.set_container_id(req.id().to_string());
        event.set_bundle(req.bundle().to_string());
        event.set_rootfs(req.rootfs().to_vec());
        event.set_io(io);
        event.set_pid(pid);
        self.publish("/tasks/create", Box::new(event)).await;
    }

    async fn publish_start(&self, task_id: &str, pid: u32) {
        let mut event = containerd_shim_protos::events::task::TaskStart::new();
        event.set_container_id(task_id.to_string());
        event.set_pid(pid);
        self.publish("/tasks/start", Box::new(event)).await;
    }

    async fn publish_exec_added(&self, task_id: &str, exec_id: &str) {
        let mut event = containerd_shim_protos::events::task::TaskExecAdded::new();
        event.set_container_id(task_id.to_string());
        event.set_exec_id(exec_id.to_string());
        self.publish("/tasks/exec-added", Box::new(event)).await;
    }

    async fn publish_exec_started(&self, task_id: &str, exec_id: &str, pid: u32) {
        let mut event = containerd_shim_protos::events::task::TaskExecStarted::new();
        event.set_container_id(task_id.to_string());
        event.set_exec_id(exec_id.to_string());
        event.set_pid(pid);
        self.publish("/tasks/exec-started", Box::new(event)).await;
    }

    async fn publish_paused(&self, task_id: &str) {
        let mut event = containerd_shim_protos::events::task::TaskPaused::new();
        event.set_container_id(task_id.to_string());
        self.publish("/tasks/paused", Box::new(event)).await;
    }

    async fn publish_resumed(&self, task_id: &str) {
        let mut event = containerd_shim_protos::events::task::TaskResumed::new();
        event.set_container_id(task_id.to_string());
        self.publish("/tasks/resumed", Box::new(event)).await;
    }

    async fn publish_delete(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        pid: u32,
        code: u32,
        exited_at: SystemTime,
    ) {
        let mut event = containerd_shim_protos::events::task::TaskDelete::new();
        event.set_container_id(task_id.to_string());
        event.set_id(exec_id.unwrap_or(task_id).to_string());
        event.set_pid(pid);
        event.set_exit_status(code);
        event.set_exited_at(timestamp_from(exited_at));
        self.publish("/tasks/delete", Box::new(event)).await;
    }

    async fn publish_exit(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        pid: u32,
        code: u32,
        exited_at: SystemTime,
    ) {
        let mut event = containerd_shim_protos::events::task::TaskExit::new();
        event.set_container_id(task_id.to_string());
        event.set_id(exec_id.unwrap_or(task_id).to_string());
        event.set_pid(pid);
        event.set_exit_status(code);
        event.set_exited_at(timestamp_from(exited_at));
        self.publish("/tasks/exit", Box::new(event)).await;
    }

    fn pump_key(task_id: &str, exec_id: Option<&str>) -> (String, String) {
        (task_id.to_string(), exec_id.unwrap_or_default().to_string())
    }

    async fn stop_task_pumps(&self, task_id: &str) {
        let pumps = {
            let mut state = self.state.lock().await;
            let keys = state
                .pumps
                .keys()
                .filter(|(candidate, _)| candidate == task_id)
                .cloned()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| state.pumps.remove(&key))
                .collect::<Vec<_>>()
        };
        for pump in pumps {
            pump.stop().await;
        }
    }

    async fn stop_all_pumps(&self) {
        let pumps = {
            let mut state = self.state.lock().await;
            std::mem::take(&mut state.pumps)
                .into_values()
                .collect::<Vec<_>>()
        };
        for pump in pumps {
            pump.stop().await;
        }
    }

    async fn wait_for_stdin_drain(&self, task_id: &str, exec_id: Option<&str>) -> TtrpcResult<()> {
        let drain = {
            let mut state = self.state.lock().await;
            if let Some(error) = &state.restore_error {
                return Err(runtime_error(error.clone()));
            }
            let key = Self::pump_key(task_id, exec_id);
            let pump = state.pumps.get_mut(&key).ok_or_else(|| {
                ttrpc_not_found(format!(
                    "containerd process I/O pump is unavailable for task {task_id} exec {:?}",
                    exec_id
                ))
            })?;
            if let Some(error) = pump.failure() {
                return Err(runtime_error(error));
            }
            pump.stdin_drain().ok_or_else(|| {
                ttrpc::Error::RpcStatus(ttrpc::get_status(
                    ttrpc::Code::FAILED_PRECONDITION,
                    format!(
                        "task {task_id} exec {:?} was not configured with containerd stdin",
                        exec_id
                    ),
                ))
            })?
        };
        drain.request_and_wait().await.map_err(runtime_error)
    }

    async fn stop_task_monitors(&self, task_id: &str) {
        let handles = {
            let mut monitors = self.monitors.lock().await;
            let keys = monitors
                .keys()
                .filter(|(candidate, _)| candidate == task_id)
                .cloned()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| monitors.remove(&key))
                .collect::<Vec<_>>()
        };
        for handle in handles {
            handle.abort.abort();
        }
    }

    async fn stop_process_monitor(&self, task_id: &str, exec_id: Option<&str>) {
        if let Some(handle) = self
            .monitors
            .lock()
            .await
            .remove(&Self::pump_key(task_id, exec_id))
        {
            handle.abort.abort();
        }
    }

    async fn stop_all_monitors(&self) {
        let handles = std::mem::take(&mut *self.monitors.lock().await)
            .into_values()
            .collect::<Vec<_>>();
        for handle in handles {
            handle.abort.abort();
        }
    }

    async fn ensure_exit_monitor(&self, task_id: &str, exec_id: Option<&str>) {
        let key = Self::pump_key(task_id, exec_id);
        let mut monitors = self.monitors.lock().await;
        if monitors.contains_key(&key) {
            return;
        }
        let owner = Arc::new(());
        let task_owner = owner.clone();
        let (start_sender, start_receiver) = tokio::sync::oneshot::channel();
        let service = self.clone();
        let monitor_key = key.clone();
        let handle = tokio::spawn(async move {
            if start_receiver.await.is_err() {
                return;
            }
            let task_id = key.0;
            let exec_id = (!key.1.is_empty()).then_some(key.1);
            let result = service.observe_exit(&task_id, exec_id.as_deref()).await;
            if let Err(error) = result {
                log::warn!(
                    "containerd exit monitor failed for task {task_id} exec {:?}: {error}",
                    exec_id
                );
                service
                    .state
                    .lock()
                    .await
                    .wait_errors
                    .insert(Self::pump_key(&task_id, exec_id.as_deref()), error);
                service.exit_notify.notify_waiters();
            }
            let mut monitors = service.monitors.lock().await;
            remove_monitor_if_owner(
                &mut monitors,
                &Self::pump_key(&task_id, exec_id.as_deref()),
                &task_owner,
            );
        });
        monitors.insert(
            monitor_key,
            ExitMonitor {
                owner,
                abort: handle.abort_handle(),
            },
        );
        let _ = start_sender.send(());
    }

    async fn observe_exit(&self, task_id: &str, exec_id: Option<&str>) -> TtrpcResult<()> {
        let snapshot = self.task_snapshot(task_id).await?;
        let adapter = self.adapter().await.map_err(runtime_error)?;
        let (exit, pid) = match exec_id {
            None => (
                adapter
                    .wait(&snapshot.identity, snapshot.record.generation)
                    .await
                    .map_err(runtime_error)?,
                record_pid(&snapshot.record),
            ),
            Some(exec_id) => {
                let exec = snapshot
                    .execs
                    .get(exec_id)
                    .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?;
                (
                    adapter
                        .wait_process(&snapshot.identity, snapshot.record.generation, exec_id)
                        .await
                        .map_err(runtime_error)?,
                    exec.record
                        .as_ref()
                        .and_then(|record| record.pid)
                        .unwrap_or(0),
                )
            }
        };
        self.record_exit(task_id, exec_id, exit, pid).await?;
        Ok(())
    }

    async fn record_exit(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        exit: ExitStatus,
        pid: u32,
    ) -> TtrpcResult<(u32, SystemTime)> {
        let code = adapter::exit_code(&exit);
        let (exited_at, first_observation) = {
            let mut state = self.state.lock().await;
            let task = state
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
            match exec_id {
                None => {
                    let first_observation = task.exit.is_none();
                    if task.exit.as_ref().is_some_and(|stored| stored != &exit) {
                        return Err(ttrpc_error(format!(
                            "runtime changed the terminal status of task {task_id}"
                        )));
                    }
                    let exited_at = *task.exited_at.get_or_insert_with(SystemTime::now);
                    task.exit = Some(exit);
                    (exited_at, first_observation)
                }
                Some(exec_id) => {
                    let exec = task
                        .execs
                        .get_mut(exec_id)
                        .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?;
                    let first_observation = exec.exit.is_none();
                    if exec.exit.as_ref().is_some_and(|stored| stored != &exit) {
                        return Err(ttrpc_error(format!(
                            "runtime changed the terminal status of exec {exec_id}"
                        )));
                    }
                    let exited_at = *exec.exited_at.get_or_insert_with(SystemTime::now);
                    exec.stage = ExecStage::Exited;
                    exec.exit = Some(exit);
                    (exited_at, first_observation)
                }
            }
        };
        self.persist_task(task_id).await?;
        if first_observation {
            self.publish_exit(task_id, exec_id, pid, code, exited_at)
                .await;
        }
        self.exit_notify.notify_waiters();
        Ok((code, exited_at))
    }

    async fn wait_for_recorded_exit(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
    ) -> TtrpcResult<(ExitStatus, u32, SystemTime)> {
        let key = Self::pump_key(task_id, exec_id);
        loop {
            let notified = self.exit_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (observed, ready_to_observe) = {
                let mut state = self.state.lock().await;
                if let Some(error) = &state.restore_error {
                    return Err(runtime_error(error.clone()));
                }
                if let Some(error) = state.wait_errors.remove(&key) {
                    return Err(error);
                }
                if let Some(error) = state.pumps.get_mut(&key).and_then(ProcessPumps::failure) {
                    return Err(runtime_error(error));
                }
                let task = state
                    .tasks
                    .get(task_id)
                    .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
                match exec_id {
                    None => (
                        task.exit.clone().map(|exit| {
                            (
                                exit,
                                record_pid(&task.record),
                                task.exited_at.unwrap_or_else(SystemTime::now),
                            )
                        }),
                        adapter::task_status(&task.record) != 1,
                    ),
                    Some(exec_id) => {
                        let exec = task
                            .execs
                            .get(exec_id)
                            .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?;
                        (
                            exec.exit.clone().map(|exit| {
                                (
                                    exit,
                                    exec.record
                                        .as_ref()
                                        .and_then(|record| record.pid)
                                        .unwrap_or(0),
                                    exec.exited_at.unwrap_or_else(SystemTime::now),
                                )
                            }),
                            exec.record.is_some(),
                        )
                    }
                }
            };
            if let Some(observed) = observed {
                return Ok(observed);
            }
            if ready_to_observe {
                self.ensure_exit_monitor(task_id, exec_id).await;
            }
            notified.await;
        }
    }

    async fn task_snapshot(&self, task_id: &str) -> TtrpcResult<TaskState> {
        let mut state = self.state.lock().await;
        if let Some(error) = &state.restore_error {
            return Err(runtime_error(error.clone()));
        }
        let keys = state
            .pumps
            .keys()
            .filter(|(candidate, _)| candidate == task_id)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(error) = state.pumps.get_mut(&key).and_then(ProcessPumps::failure) {
                return Err(runtime_error(error));
            }
        }
        state
            .tasks
            .get(task_id)
            .cloned()
            .ok_or_else(|| ttrpc_not_found(format!("unknown containerd task {task_id}")))
    }

    async fn refresh_task(&self, task_id: &str) -> TtrpcResult<TaskState> {
        let snapshot = self.task_snapshot(task_id).await?;
        let adapter = self.adapter().await.map_err(runtime_error)?;
        let record = adapter
            .exact_state(&snapshot.identity, snapshot.record.generation)
            .await
            .map_err(runtime_error)?;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_error(format!("task {task_id} disappeared during state")))?;
        task.record = record;
        Ok(task.clone())
    }

    async fn mount_rootfs(&self, req: &api::CreateTaskRequest) -> TtrpcResult<bool> {
        if req.rootfs().is_empty() {
            return Ok(false);
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::FAILED_PRECONDITION,
                "containerd snapshotter rootfs mounts are currently supported only on Linux"
                    .to_string(),
            )))
        }
        #[cfg(target_os = "linux")]
        {
            let rootfs = Path::new(req.bundle()).join("rootfs");
            tokio::fs::create_dir_all(&rootfs).await.map_err(|error| {
                ttrpc_error(format!(
                    "failed to prepare containerd rootfs {}: {error}",
                    rootfs.display()
                ))
            })?;
            for mount in req.rootfs() {
                if let Err(error) =
                    containerd_shim::asynchronous::util::mount_rootfs(mount, &rootfs).await
                {
                    let _ = Self::unmount_rootfs(rootfs.clone()).await;
                    return Err(ttrpc_error(format!(
                        "failed to mount containerd rootfs component at {}: {error}",
                        rootfs.display()
                    )));
                }
            }
            Ok(true)
        }
    }

    async fn unmount_rootfs(_rootfs: PathBuf) -> TtrpcResult<()> {
        #[cfg(target_os = "linux")]
        {
            let rootfs = _rootfs;
            let display = rootfs.display().to_string();
            containerd_shim::asynchronous::util::asyncify(move || {
                let target = rootfs.to_str().ok_or_else(|| {
                    containerd_shim::Error::InvalidArgument(
                        "containerd rootfs path is not valid UTF-8".to_string(),
                    )
                })?;
                containerd_shim::mount::umount_recursive(Some(target), 0)
            })
            .await
            .map_err(|error| {
                ttrpc_error(format!(
                    "failed to unmount containerd rootfs {display}: {error}"
                ))
            })?;
        }
        Ok(())
    }
}

#[async_trait]
impl Shim for Service {
    type T = Service;

    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        let requested_bundle = if args.bundle.is_empty() {
            std::env::current_dir().unwrap_or_default()
        } else {
            PathBuf::from(&args.bundle)
        };
        let (bundle, restore_error) = match tokio::fs::canonicalize(&requested_bundle).await {
            Ok(bundle) => (bundle, None),
            Err(error) => (
                requested_bundle.clone(),
                Some(
                    RuntimeError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "failed to resolve containerd shim bundle {}: {error}",
                            requested_bundle.display()
                        ),
                    )
                    .for_operation("containerd-shim-bundle"),
                ),
            ),
        };
        Self {
            namespace: args.namespace.clone(),
            task_id: args.id.clone(),
            endpoint: Self::endpoint_from_environment(),
            bundle,
            exit: Arc::new(ExitSignal::default()),
            state: Arc::new(Mutex::new(ServiceState {
                restore_error,
                ..ServiceState::default()
            })),
            metadata_gate: Arc::new(Mutex::new(())),
            monitors: Arc::new(Mutex::new(BTreeMap::new())),
            exit_notify: Arc::new(Notify::new()),
            publisher: None,
            #[cfg(test)]
            test_adapter: Arc::new(Mutex::new(None)),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        let grouping = opts.id.clone();
        spawn(opts, &grouping, Vec::new()).await
    }

    async fn delete_shim(&mut self) -> Result<api::DeleteResponse, Error> {
        self.stop_all_monitors().await;
        self.stop_all_pumps().await;
        let mut response = api::DeleteResponse::new();
        let metadata = ShimMetadata::load(&self.metadata_path())
            .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
        if let Some(metadata) = metadata {
            let identity = metadata
                .identity()
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
            let adapter = self
                .adapter()
                .await
                .map_err(|error| Error::Other(error.to_string()))?;
            let record = match adapter.exact_state(&identity, metadata.generation()).await {
                Ok(record) => Some(record),
                Err(error) if error.code == ErrorCode::NotFound => {
                    match adapter
                        .delete(&identity, metadata.generation(), false)
                        .await
                    {
                        Ok(()) => {}
                        Err(error) if error.code == ErrorCode::NotFound => adapter
                            .delete(&identity, metadata.generation(), true)
                            .await
                            .map_err(|error| Error::Other(error.to_string()))?,
                        Err(error) => return Err(Error::Other(error.to_string())),
                    }
                    None
                }
                Err(error) => return Err(Error::Other(error.to_string())),
            };
            if let Some(observed) = record.as_ref() {
                if observed.state.id() != identity.container_id.as_str()
                    || observed.generation != metadata.generation()
                    || observed.driver != metadata.driver()
                    || observed.isolation != metadata.isolation()
                {
                    return Err(Error::FailedPreconditionError(
                        "runtime state no longer matches the persisted containerd shim identity, generation, driver, or isolation"
                            .to_string(),
                    ));
                }
            }
            let pid = record.as_ref().map_or(0, record_pid);
            let mut exit = metadata.exit().cloned();
            if record.as_ref().is_some_and(ContainerRecord::is_paused) {
                adapter
                    .delete(&identity, metadata.generation(), true)
                    .await
                    .map_err(|error| Error::Other(error.to_string()))?;
            } else if record.is_some() {
                if exit.is_none() {
                    let _ = adapter
                        .kill(&identity, metadata.generation(), 9, true)
                        .await;
                    exit = tokio::time::timeout(
                        DELETE_SHIM_WAIT_TIMEOUT,
                        adapter.wait(&identity, metadata.generation()),
                    )
                    .await
                    .ok()
                    .and_then(|result| result.ok());
                }
                adapter
                    .delete(&identity, metadata.generation(), true)
                    .await
                    .map_err(|error| Error::Other(error.to_string()))?;
            }
            ShimCreateIntent::remove(metadata.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            if metadata.rootfs_mounted() {
                Self::unmount_rootfs(metadata.bundle().join("rootfs"))
                    .await
                    .map_err(Error::from)?;
            }
            ShimMetadata::remove(metadata.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            response.set_pid(pid);
            response.set_exit_status(exit.as_ref().map_or(137, adapter::exit_code));
            response.set_exited_at(timestamp_from(
                metadata
                    .exited_at_unix_nanos()
                    .and_then(system_time_from_unix_nanos)
                    .unwrap_or_else(SystemTime::now),
            ));
        } else if let Some(intent) =
            ShimCreateIntent::load(&ShimCreateIntent::path(&self.bundle))
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?
        {
            let identity = intent
                .identity()
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
            let adapter = self
                .adapter()
                .await
                .map_err(|error| Error::Other(error.to_string()))?
                .with_isolation(intent.isolation().clone());
            let record = adapter
                .replay_create_for_cleanup(
                    &identity,
                    intent.bundle(),
                    adapter::process_io(
                        intent.terminal(),
                        !intent.stdin().is_empty(),
                        !intent.stdout().is_empty(),
                        !intent.stderr().is_empty(),
                    ),
                )
                .await
                .map_err(|error| Error::Other(error.to_string()))?;
            let pid = record_pid(&record);
            let _ = adapter.kill(&identity, record.generation, 9, true).await;
            let exit = tokio::time::timeout(
                DELETE_SHIM_WAIT_TIMEOUT,
                adapter.wait(&identity, record.generation),
            )
            .await
            .ok()
            .and_then(|result| result.ok());
            adapter
                .delete(&identity, record.generation, true)
                .await
                .map_err(|error| Error::Other(error.to_string()))?;
            ShimCreateIntent::remove(intent.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            if intent.rootfs_mounted() {
                Self::unmount_rootfs(intent.bundle().join("rootfs"))
                    .await
                    .map_err(Error::from)?;
            }
            response.set_pid(pid);
            response.set_exit_status(exit.as_ref().map_or(137, adapter::exit_code));
            response.set_exited_at(timestamp_now());
        } else {
            response.set_exited_at(timestamp_now());
        }
        Ok(response)
    }

    async fn wait(&mut self) {
        self.exit.wait().await;
    }

    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        let mut service = self.clone();
        service.publisher = Some(Arc::new(publisher));
        if !service.task_id.is_empty() {
            if let Err(error) = service.restore_task(&service.task_id).await {
                log::error!("failed to rehydrate containerd shim state: {error}");
                service.state.lock().await.restore_error = Some(error);
            }
        }
        service
    }
}

fn record_pid(record: &ContainerRecord) -> u32 {
    record
        .state
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .unwrap_or(0)
}

fn remove_monitor_if_owner(
    monitors: &mut BTreeMap<(String, String), ExitMonitor>,
    key: &(String, String),
    owner: &Arc<()>,
) -> bool {
    if monitors
        .get(key)
        .is_some_and(|monitor| Arc::ptr_eq(&monitor.owner, owner))
    {
        monitors.remove(key);
        true
    } else {
        false
    }
}

fn protobuf_status(status: i32) -> protobuf::EnumOrUnknown<api::Status> {
    protobuf::EnumOrUnknown::new(match status {
        1 => api::Status::CREATED,
        2 => api::Status::RUNNING,
        3 => api::Status::STOPPED,
        _ => api::Status::UNKNOWN,
    })
}

fn protobuf_task_status(
    record: &ContainerRecord,
    exit_observed: bool,
) -> protobuf::EnumOrUnknown<api::Status> {
    if exit_observed {
        protobuf::EnumOrUnknown::new(api::Status::STOPPED)
    } else if record.is_paused() {
        protobuf::EnumOrUnknown::new(api::Status::PAUSED)
    } else {
        protobuf_status(adapter::task_status(record))
    }
}

fn protobuf_exec_status(
    task: &ContainerRecord,
    exec: &ExecState,
) -> protobuf::EnumOrUnknown<api::Status> {
    if exec.exit.is_some() {
        protobuf::EnumOrUnknown::new(api::Status::STOPPED)
    } else if exec.record.is_none() {
        protobuf::EnumOrUnknown::new(api::Status::CREATED)
    } else if task.is_paused() {
        protobuf::EnumOrUnknown::new(api::Status::PAUSED)
    } else {
        protobuf::EnumOrUnknown::new(api::Status::RUNNING)
    }
}

fn timestamp_now() -> protobuf::well_known_types::timestamp::Timestamp {
    timestamp_from(SystemTime::now())
}

fn timestamp_from(time: SystemTime) -> protobuf::well_known_types::timestamp::Timestamp {
    let now = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut timestamp = protobuf::well_known_types::timestamp::Timestamp::new();
    timestamp.seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    timestamp.nanos = i32::try_from(now.subsec_nanos()).unwrap_or_default();
    timestamp
}

fn system_time_from_unix_nanos(nanos: u128) -> Option<SystemTime> {
    let seconds = u64::try_from(nanos / 1_000_000_000).ok()?;
    let subsecond_nanos = u32::try_from(nanos % 1_000_000_000).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::new(seconds, subsecond_nanos))
}

fn system_time_to_unix_nanos(time: SystemTime) -> Option<u128> {
    let duration = time.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    Some(u128::from(duration.as_secs()) * 1_000_000_000 + u128::from(duration.subsec_nanos()))
}

fn metadata_from_task(task: &TaskState) -> ShimMetadata {
    let mut metadata = ShimMetadata::new(NewShimMetadata {
        identity: task.identity.clone(),
        generation: task.record.generation,
        driver: task.record.driver,
        isolation: task.record.isolation,
        bundle: task.bundle.clone(),
        stdin: task.stdin.clone(),
        stdout: task.stdout.clone(),
        stderr: task.stderr.clone(),
        terminal: task.terminal,
        output_cursor: task.output_cursor,
        rootfs_mounted: task.rootfs_mounted,
    });
    metadata.set_control_state(
        task.control_sequence,
        task.pending_control.clone(),
        task.last_update_digest.clone(),
    );
    metadata.set_stdin_state(task.stdin_sequence, task.pending_stdin_write.clone());
    metadata.set_exit(
        task.exit.clone(),
        task.exited_at.and_then(system_time_to_unix_nanos),
    );
    metadata.set_execs(
        task.execs
            .iter()
            .map(|(exec_id, exec)| {
                let mut metadata = ExecMetadata::new(
                    exec_id.clone(),
                    exec.process.clone(),
                    exec.stdin.clone(),
                    exec.stdout.clone(),
                    exec.stderr.clone(),
                    exec.terminal,
                );
                metadata.record = exec.record.clone();
                metadata.stage = exec.stage;
                metadata.stdin_sequence = exec.stdin_sequence;
                metadata.pending_stdin_write = exec.pending_stdin_write.clone();
                metadata.output_cursor = exec.output_cursor;
                metadata.exit = exec.exit.clone();
                metadata.exited_at_unix_nanos = exec.exited_at.and_then(system_time_to_unix_nanos);
                metadata
            })
            .collect(),
    );
    metadata
}

fn runtime_error(error: RuntimeError) -> ttrpc::Error {
    let code = match error.code {
        ErrorCode::InvalidArgument => ttrpc::Code::INVALID_ARGUMENT,
        ErrorCode::NotFound => ttrpc::Code::NOT_FOUND,
        ErrorCode::AlreadyExists => ttrpc::Code::ALREADY_EXISTS,
        ErrorCode::PermissionDenied => ttrpc::Code::PERMISSION_DENIED,
        ErrorCode::ResourceExhausted => ttrpc::Code::RESOURCE_EXHAUSTED,
        ErrorCode::FailedPrecondition => ttrpc::Code::FAILED_PRECONDITION,
        ErrorCode::Unsupported => ttrpc::Code::UNIMPLEMENTED,
        ErrorCode::DeadlineExceeded => ttrpc::Code::DEADLINE_EXCEEDED,
        ErrorCode::Conflict => ttrpc::Code::ABORTED,
        ErrorCode::Unavailable => ttrpc::Code::UNAVAILABLE,
        ErrorCode::Internal => ttrpc::Code::INTERNAL,
        _ => ttrpc::Code::INTERNAL,
    };
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, error.to_string()))
}

fn ttrpc_error(message: String) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::UNKNOWN, message))
}

fn ttrpc_invalid_argument(message: String) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::INVALID_ARGUMENT, message))
}

fn ttrpc_not_found(message: String) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::NOT_FOUND, message))
}

fn ttrpc_already_exists(message: String) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::ALREADY_EXISTS, message))
}
