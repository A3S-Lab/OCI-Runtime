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

use crate::adapter::{self, ExecIdentity, RuntimeAdapter, TaskIdentity};
use crate::contract::{DEFAULT_UNIX_ENDPOINT, LEGACY_RUNTIME_ENDPOINT_ENV, RUNTIME_ENDPOINT_ENV};
use crate::io::{self, ProcessIoEndpoints, ProcessPumps};
use crate::metadata::{
    ControlOperationKind, ExecDeleteJournal, ExecDeleteReceipt, ExecMetadata, ExecStage,
    NewShimCreateIntent, NewShimMetadata, PendingControlOperation, PendingResize, PendingSignal,
    PendingStdinWrite, RestoreState, ShimCreateIntent, ShimMetadata, StdinCloseState,
    TaskDeleteReceipt,
};

mod control;
mod journal;
mod resize;
mod restore;
mod shim;
mod signal;
mod task;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
struct TaskState {
    identity: TaskIdentity,
    bundle: PathBuf,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    restore_state: RestoreState,
    stdin_sequence: u64,
    pending_stdin_write: Option<PendingStdinWrite>,
    stdin_close_state: StdinCloseState,
    resize_gate: Arc<Mutex<()>>,
    resize_sequence: u64,
    pending_resize: Option<PendingResize>,
    terminal_size: Option<TerminalSize>,
    signal_gate: Arc<Mutex<()>>,
    signal_sequence: u64,
    pending_signal: Option<PendingSignal>,
    output_cursor: u64,
    control_gate: Arc<Mutex<()>>,
    control_sequence: u64,
    pending_control: Option<PendingControlOperation>,
    last_update_digest: Option<String>,
    rootfs_mounted: bool,
    record: ContainerRecord,
    exit: Option<ExitStatus>,
    exited_at: Option<SystemTime>,
    exec_sequence: u64,
    execs: BTreeMap<String, ExecState>,
}

#[derive(Debug, Clone)]
struct ExecState {
    incarnation: u64,
    process: Process,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    stdin_sequence: u64,
    pending_stdin_write: Option<PendingStdinWrite>,
    stdin_close_state: StdinCloseState,
    resize_gate: Arc<Mutex<()>>,
    resize_sequence: u64,
    pending_resize: Option<PendingResize>,
    terminal_size: Option<TerminalSize>,
    signal_gate: Arc<Mutex<()>>,
    signal_sequence: u64,
    pending_signal: Option<PendingSignal>,
    output_cursor: u64,
    stage: ExecStage,
    record: Option<ProcessRecord>,
    exit: Option<ExitStatus>,
    exited_at: Option<SystemTime>,
}

impl ExecState {
    fn identity(&self, exec_id: &str) -> Result<ExecIdentity, RuntimeError> {
        ExecIdentity::new(exec_id, self.incarnation)
    }
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

impl Service {
    fn endpoint_from_environment() -> String {
        std::env::var(RUNTIME_ENDPOINT_ENV)
            .or_else(|_| std::env::var(LEGACY_RUNTIME_ENDPOINT_ENV))
            .unwrap_or_else(|_| DEFAULT_UNIX_ENDPOINT.to_string())
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
        event.set_checkpoint(req.checkpoint().to_string());
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

    async fn publish_checkpointed(&self, task_id: &str, checkpoint: &str) {
        let mut event = containerd_shim_protos::events::task::TaskCheckpointed::new();
        event.set_container_id(task_id.to_string());
        event.set_checkpoint(checkpoint.to_string());
        self.publish("/tasks/checkpointed", Box::new(event)).await;
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
                    "containerd process I/O pump is unavailable for task {task_id} exec {exec_id:?}"
                ))
            })?;
            if let Some(error) = pump.failure() {
                return Err(runtime_error(error));
            }
            pump.stdin_drain().ok_or_else(|| {
                ttrpc::Error::RpcStatus(ttrpc::get_status(
                    ttrpc::Code::FAILED_PRECONDITION,
                    format!(
                        "task {task_id} exec {exec_id:?} was not configured with containerd stdin"
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
        let exec_identity = match exec_id {
            Some(exec_id) => {
                let identity = self
                    .state
                    .lock()
                    .await
                    .tasks
                    .get(task_id)
                    .and_then(|task| task.execs.get(exec_id))
                    .map(|exec| exec.identity(exec_id));
                match identity {
                    Some(Ok(identity)) => Some(identity),
                    Some(Err(error)) => {
                        log::warn!(
                            "could not monitor containerd task {task_id} exec {exec_id}: {error}"
                        );
                        return;
                    }
                    None => return,
                }
            }
            None => None,
        };
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
            let result = service.observe_exit(&task_id, exec_identity.as_ref()).await;
            let owned = {
                let mut monitors = service.monitors.lock().await;
                remove_monitor_if_owner(
                    &mut monitors,
                    &Self::pump_key(&task_id, exec_id.as_deref()),
                    &task_owner,
                )
            };
            if let Err(error) = result {
                if !owned {
                    return;
                }
                log::warn!(
                    "containerd exit monitor failed for task {task_id} exec {exec_id:?}: {error}"
                );
                let mut state = service.state.lock().await;
                let still_current = match exec_identity.as_ref() {
                    None => state.tasks.contains_key(&task_id),
                    Some(identity) => state
                        .tasks
                        .get(&task_id)
                        .and_then(|task| task.execs.get(identity.exec_id()))
                        .is_some_and(|exec| exec.incarnation == identity.incarnation()),
                };
                if still_current {
                    state
                        .wait_errors
                        .insert(Self::pump_key(&task_id, exec_id.as_deref()), error);
                    drop(state);
                    service.exit_notify.notify_waiters();
                }
            }
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

    async fn observe_exit(
        &self,
        task_id: &str,
        exec_identity: Option<&ExecIdentity>,
    ) -> TtrpcResult<()> {
        let snapshot = self.task_snapshot(task_id).await?;
        let adapter = self.adapter().await.map_err(runtime_error)?;
        let (exit, pid) = match exec_identity {
            None => (
                adapter
                    .wait(&snapshot.identity, snapshot.record.generation)
                    .await
                    .map_err(runtime_error)?,
                record_pid(&snapshot.record),
            ),
            Some(exec_identity) => {
                let exec_id = exec_identity.exec_id();
                let exec = snapshot
                    .execs
                    .get(exec_id)
                    .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?;
                if exec.incarnation != exec_identity.incarnation() {
                    return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                        ttrpc::Code::ABORTED,
                        format!(
                            "exec {exec_id} incarnation {} was replaced by incarnation {}",
                            exec_identity.incarnation(),
                            exec.incarnation
                        ),
                    )));
                }
                (
                    adapter
                        .wait_process(
                            &snapshot.identity,
                            snapshot.record.generation,
                            exec_identity,
                        )
                        .await
                        .map_err(runtime_error)?,
                    exec.record
                        .as_ref()
                        .and_then(|record| record.pid)
                        .unwrap_or(0),
                )
            }
        };
        self.record_exit(task_id, exec_identity, exit, pid).await?;
        Ok(())
    }

    async fn record_exit(
        &self,
        task_id: &str,
        exec_identity: Option<&ExecIdentity>,
        exit: ExitStatus,
        pid: u32,
    ) -> TtrpcResult<(u32, SystemTime)> {
        let _metadata_guard = self.metadata_gate.lock().await;
        let exec_id = exec_identity.map(ExecIdentity::exec_id);
        let code = adapter::exit_code(&exit);
        let (snapshot, exited_at, first_observation) = {
            let mut state = self.state.lock().await;
            let task = state
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
            let (exited_at, first_observation) = match exec_identity {
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
                Some(exec_identity) => {
                    let exec_id = exec_identity.exec_id();
                    let exec = task
                        .execs
                        .get_mut(exec_id)
                        .ok_or_else(|| ttrpc_not_found(format!("unknown exec {exec_id}")))?;
                    let expected_incarnation = exec_identity.incarnation();
                    if exec.incarnation != expected_incarnation {
                        return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                            ttrpc::Code::ABORTED,
                            format!(
                                "exec {exec_id} incarnation {expected_incarnation} was replaced by incarnation {}",
                                exec.incarnation
                            ),
                        )));
                    }
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
            };
            (task.clone(), exited_at, first_observation)
        };
        metadata_from_task(&snapshot)
            .store()
            .map_err(runtime_error)?;
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
    task: &TaskState,
    exit_observed: bool,
) -> protobuf::EnumOrUnknown<api::Status> {
    if exit_observed {
        protobuf::EnumOrUnknown::new(api::Status::STOPPED)
    } else if task.restore_state == RestoreState::PendingStart {
        protobuf::EnumOrUnknown::new(api::Status::CREATED)
    } else if task.record.is_paused() {
        protobuf::EnumOrUnknown::new(api::Status::PAUSED)
    } else {
        protobuf_status(adapter::task_status(&task.record))
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

fn exec_delete_response(
    receipt: &ExecDeleteReceipt,
) -> Result<(api::DeleteResponse, SystemTime), RuntimeError> {
    let exited_at =
        system_time_from_unix_nanos(receipt.exited_at_unix_nanos()).ok_or_else(|| {
            RuntimeError::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "containerd exec {} delete receipt records an unrepresentable exit time",
                    receipt.exec_id()
                ),
            )
            .for_operation("containerd-delete-process-replay")
        })?;
    let mut response = api::DeleteResponse::new();
    response.set_pid(receipt.pid());
    response.set_exit_status(receipt.exit_status());
    response.set_exited_at(timestamp_from(exited_at));
    Ok((response, exited_at))
}

fn task_delete_response(
    receipt: &TaskDeleteReceipt,
) -> Result<(api::DeleteResponse, SystemTime), RuntimeError> {
    let exited_at = receipt.exited_at().ok_or_else(|| {
        RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "containerd task delete receipt records an unrepresentable exit time",
        )
        .for_operation("containerd-delete-task-replay")
    })?;
    let mut response = api::DeleteResponse::new();
    response.set_pid(receipt.pid());
    response.set_exit_status(receipt.exit_status());
    response.set_exited_at(timestamp_from(exited_at));
    Ok((response, exited_at))
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
        restore_state: task.restore_state,
        output_cursor: task.output_cursor,
        rootfs_mounted: task.rootfs_mounted,
    });
    metadata.set_control_state(
        task.control_sequence,
        task.pending_control.clone(),
        task.last_update_digest.clone(),
    );
    if task.pending_control.as_ref().is_some_and(|operation| {
        operation.kind() == ControlOperationKind::Update && operation.resources().is_none()
    }) {
        metadata.preserve_legacy_pending_update_schema();
    }
    metadata.set_stdin_state(
        task.stdin_sequence,
        task.pending_stdin_write.clone(),
        task.stdin_close_state,
    );
    metadata.set_resize_state(
        task.resize_sequence,
        task.pending_resize.clone(),
        task.terminal_size,
    );
    metadata.set_signal_state(task.signal_sequence, task.pending_signal.clone());
    metadata.set_exit(
        task.exit.clone(),
        task.exited_at.and_then(system_time_to_unix_nanos),
    );
    metadata.set_exec_sequence(task.exec_sequence);
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
                metadata.incarnation = exec.incarnation;
                metadata.record = exec.record.clone();
                metadata.stage = exec.stage;
                metadata.stdin_sequence = exec.stdin_sequence;
                metadata.pending_stdin_write = exec.pending_stdin_write.clone();
                metadata.stdin_close_state = exec.stdin_close_state;
                metadata.resize_sequence = exec.resize_sequence;
                metadata.pending_resize = exec.pending_resize.clone();
                metadata.terminal_size = exec.terminal_size;
                metadata.signal_sequence = exec.signal_sequence;
                metadata.pending_signal = exec.pending_signal.clone();
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
