mod capability;
mod cgroup;
mod control;
mod device;
mod exec;
mod exec_process;
mod init;
mod io;
mod mount;
#[cfg(test)]
mod mount_tests;
mod namespace;
mod pid;
mod pid_supervisor;
mod pidfd;
mod plan;
#[cfg(test)]
mod plan_tests;
mod process;
mod process_io;
mod rootfs;
#[cfg(test)]
mod rootfs_tests;
mod seccomp;
#[cfg(test)]
mod seccomp_tests;
mod state;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCloseStdinRequest, AgentContainerOperationRequest, AgentCreateRequest,
    AgentDeleteRequest, AgentExecRequest, AgentKillRequest, AgentProcess, AgentProcessesRequest,
    AgentReadOutputRequest, AgentSignalProcessRequest, AgentStartRequest, AgentState,
    AgentStateRequest, AgentStatsRequest, AgentUpdateRequest, AgentWaitProcessRequest,
    AgentWaitRequest, AgentWriteStdinRequest, GuestAgentService,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerStats, DeleteMode, Error, ErrorCode, ExitStatus, OperationContext,
    OutputChunk, ProcessRecord, Result,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use crate::AGENT_VERSION;
use cgroup::CgroupManager;
use pidfd::SignalOutcome;
use plan::InitPlan;
use process::PreparedProcess;
use state::{
    ContainerKey, ContainerRecord, ExecutorState, MutationKind, RecordedOutcome, RecordedRequest,
};

pub(crate) use pidfd::verify_support as verify_pidfd_support;

const DEFAULT_RUNTIME_PARENT: &str = "/run";
const MAX_OPERATION_RECORDS: usize = 4_096;
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) fn run_container_init_if_requested() -> Option<Result<()>> {
    init::run_container_init_if_requested().or_else(exec_process::run_container_exec_if_requested)
}

/// Fail-closed Linux OCI executor shared by native and utility-VM drivers.
#[derive(Debug)]
pub struct LinuxExecutor {
    capabilities: AgentCapabilities,
    init_executable: PathBuf,
    runtime_root: PathBuf,
    state: Mutex<ExecutorState>,
}

impl LinuxExecutor {
    pub(crate) async fn new() -> Result<Self> {
        let executable = std::env::current_exe().map_err(|error| {
            executor_error(
                ErrorCode::Internal,
                format!("failed to resolve guest-agent executable: {error}"),
            )
        })?;
        Self::open(DEFAULT_RUNTIME_PARENT, executable).await
    }

    /// Open an isolated executor beneath an existing runtime-owned directory.
    ///
    /// The init executable must enter [`crate::run_internal_container_init`]
    /// before starting its normal application path.
    pub async fn open(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
    ) -> Result<Self> {
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(executor_error(
                ErrorCode::PermissionDenied,
                "the Linux executor must run as root",
            ));
        }
        pidfd::verify_support()?;
        let parent = runtime_parent.as_ref();
        if !parent.is_absolute() {
            return Err(executor_error(
                ErrorCode::InvalidArgument,
                format!(
                    "Linux executor runtime parent must be absolute: {}",
                    parent.display()
                ),
            ));
        }
        let metadata = tokio::fs::symlink_metadata(parent).await.map_err(|error| {
            executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect Linux executor runtime parent {}: {error}",
                    parent.display()
                ),
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "Linux executor runtime parent must be a real directory: {}",
                    parent.display()
                ),
            ));
        }
        let init_executable = tokio::fs::canonicalize(init_executable.as_ref())
            .await
            .map_err(|error| {
                executor_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "failed to resolve Linux executor init executable {}: {error}",
                        init_executable.as_ref().display()
                    ),
                )
            })?;
        let init_metadata = tokio::fs::metadata(&init_executable)
            .await
            .map_err(|error| {
                executor_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "failed to inspect Linux executor init executable {}: {error}",
                        init_executable.display()
                    ),
                )
            })?;
        if !init_metadata.is_file() {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "Linux executor init executable must be a regular file: {}",
                    init_executable.display()
                ),
            ));
        }
        let runtime_root = parent.join(format!("a3s-oci-agent-{}", std::process::id()));
        let mut builder = tokio::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&runtime_root).await.map_err(|error| {
            executor_error(
                ErrorCode::Conflict,
                format!(
                    "failed to create exclusive guest runtime root {}: {error}",
                    runtime_root.display()
                ),
            )
        })?;

        Ok(Self {
            capabilities: AgentCapabilities::linux_executor(AGENT_VERSION, std::env::consts::ARCH)?,
            init_executable,
            runtime_root,
            state: Mutex::new(ExecutorState::default()),
        })
    }

    /// Absolute private directory holding this executor's transient state.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Stop every owned init process and remove all transient executor state.
    pub async fn shutdown(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut first_error = None;
        for record in state.containers.values_mut() {
            if let Err(error) = record.force_stop_all().await {
                first_error.get_or_insert(error);
            }
        }
        state.containers.clear();
        if let Some(manager) = state.cgroup_manager.take() {
            if let Err(error) = manager.remove() {
                first_error.get_or_insert(error);
            }
        }
        match tokio::fs::remove_dir_all(&self.runtime_root).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                first_error.get_or_insert_with(|| {
                    executor_error(
                        ErrorCode::Internal,
                        format!(
                            "failed to remove guest runtime root {}: {error}",
                            self.runtime_root.display()
                        ),
                    )
                });
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn create_new(
        &self,
        state: &mut ExecutorState,
        request: &AgentCreateRequest,
    ) -> Result<AgentState> {
        validate_deadline(&request.context)?;
        let key = ContainerKey::from_target(&request.target)?;
        if state
            .containers
            .keys()
            .any(|candidate| candidate.id == key.id)
        {
            return Err(executor_error(
                ErrorCode::AlreadyExists,
                format!("container {} already exists in the guest", key.id),
            ));
        }
        if state
            .highest_generations
            .get(&key.id)
            .is_some_and(|generation| key.generation <= *generation)
        {
            return Err(executor_error(
                ErrorCode::Conflict,
                format!(
                    "container {} generation {} is not newer than the guest fence",
                    key.id, key.generation
                ),
            ));
        }

        let bundle = request.bundle.to_guest_bundle()?;
        let plan = InitPlan::from_bundle(&bundle, &request.io)?;
        if plan.cgroup.has_cgroup() && state.cgroup_manager.is_none() {
            state.cgroup_manager = Some(CgroupManager::create()?);
        }
        let slot = state.next_slot.checked_add(1).ok_or_else(|| {
            executor_error(
                ErrorCode::ResourceExhausted,
                "guest container slot space is exhausted",
            )
        })?;
        state.next_slot = slot;
        let runtime_directory = self.runtime_root.join(format!("c-{slot:016x}"));
        create_private_directory(&runtime_directory).await?;
        let config_snapshot = runtime_directory.join("config.json");
        if let Err(error) =
            write_private_snapshot(&config_snapshot, request.bundle.config_json()).await
        {
            let _ = remove_container_directory(&self.runtime_root, &runtime_directory).await;
            return Err(error);
        }
        let process = match PreparedProcess::spawn(
            &plan,
            &config_snapshot,
            &self.init_executable,
            state.cgroup_manager.as_ref(),
            &request.io,
        )
        .await
        {
            Ok(process) => process,
            Err(error) => {
                let _ = remove_container_directory(&self.runtime_root, &runtime_directory).await;
                return Err(error);
            }
        };
        let response = AgentState::new(
            request.target.clone(),
            ContainerState::Created,
            Some(process.pid()),
            request.bundle.config_digest(),
        )?;
        state
            .highest_generations
            .insert(key.id.clone(), key.generation);
        state.containers.insert(
            key,
            ContainerRecord {
                target: request.target.clone(),
                config_digest: request.bundle.config_digest().to_string(),
                status: ContainerState::Created,
                paused: false,
                process,
                processes: BTreeMap::new(),
                runtime_directory,
            },
        );
        Ok(response)
    }

    async fn start_new(
        state: &mut ExecutorState,
        request: &AgentStartRequest,
    ) -> Result<AgentState> {
        validate_deadline(&request.context)?;
        let key = ContainerKey::from_target(&request.target)?;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.refresh()?;
        if record.config_digest != request.expected_config_digest {
            return Err(executor_error(
                ErrorCode::Conflict,
                "start configuration digest does not match guest create state",
            ));
        }
        if record.status != ContainerState::Created {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!("container cannot start from {}", record.status),
            ));
        }
        record.process.release().await?;
        record.status = ContainerState::Running;
        record.state()
    }

    fn state_new(state: &mut ExecutorState, request: &AgentStateRequest) -> Result<AgentState> {
        let key = ContainerKey::from_target(&request.target)?;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.refresh()?;
        record.state()
    }

    async fn freezer_new(
        state: &mut ExecutorState,
        request: &AgentContainerOperationRequest,
        frozen: bool,
    ) -> Result<AgentState> {
        validate_deadline(&request.context)?;
        let key = ContainerKey::from_target(&request.target)?;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.set_frozen(frozen).await?;
        record.state()
    }

    fn processes_new(
        state: &mut ExecutorState,
        request: &AgentProcessesRequest,
    ) -> Result<Vec<ProcessRecord>> {
        let key = ContainerKey::from_target(&request.target)?;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.live_processes()
    }

    async fn update_new(
        state: &mut ExecutorState,
        request: &AgentUpdateRequest,
    ) -> Result<AgentState> {
        validate_deadline(&request.context)?;
        let key = ContainerKey::from_target(&request.target)?;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.update_resources(&request.resources).await?;
        record.state()
    }

    async fn stats_new(
        state: &mut ExecutorState,
        request: &AgentStatsRequest,
    ) -> Result<ContainerStats> {
        let key = ContainerKey::from_target(&request.target)?;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.stats().await
    }

    fn kill_new(state: &mut ExecutorState, request: &AgentKillRequest) -> Result<AgentState> {
        validate_deadline(&request.context)?;
        if request.all {
            return Err(executor_error(
                ErrorCode::Unsupported,
                "process-group signaling is not implemented by the bootstrap executor",
            ));
        }
        let key = ContainerKey::from_target(&request.target)?;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.refresh()?;
        if record.status == ContainerState::Stopped {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                "cannot signal a stopped container",
            ));
        }
        match record.process.signal(request.signal.get())? {
            SignalOutcome::Delivered => record.refresh()?,
            SignalOutcome::Exited => record.status = ContainerState::Stopped,
        }
        record.state()
    }

    async fn delete_new(
        &self,
        state: &mut ExecutorState,
        request: &AgentDeleteRequest,
    ) -> Result<()> {
        validate_deadline(&request.context)?;
        let key = ContainerKey::from_target(&request.target)?;
        let runtime_directory = {
            let record = state.containers.get_mut(&key).ok_or_else(|| {
                executor_error(
                    ErrorCode::NotFound,
                    format!(
                        "container {} generation {} does not exist",
                        key.id, key.generation
                    ),
                )
            })?;
            record.refresh()?;
            if record.status != ContainerState::Stopped && request.mode == DeleteMode::StoppedOnly {
                return Err(executor_error(
                    ErrorCode::FailedPrecondition,
                    "stopped-only delete requires a stopped container",
                ));
            }
            // Even an already-stopped init may have an authenticated wrapper
            // that has not completed its final wait yet. Always reap that
            // wrapper before releasing the runtime directory.
            record.force_stop_all().await?;
            record.status = ContainerState::Stopped;
            record.runtime_directory.clone()
        };
        remove_container_directory(&self.runtime_root, &runtime_directory).await?;
        state.containers.remove(&key);
        Ok(())
    }

    async fn wait_new(&self, request: &AgentWaitRequest) -> Result<ExitStatus> {
        let key = ContainerKey::from_target(&request.target)?;
        let timeout = request.timeout_ms.map(Duration::from_millis);
        let started = Instant::now();
        loop {
            let status = {
                let mut state = self.state.lock().await;
                let record = state.containers.get_mut(&key).ok_or_else(|| {
                    executor_error(
                        ErrorCode::NotFound,
                        format!(
                            "container {} generation {} does not exist",
                            key.id, key.generation
                        ),
                    )
                })?;
                record.poll_wait()?
            };
            if let Some(status) = status {
                return Ok(status);
            }

            let delay = match timeout {
                Some(limit) => {
                    let elapsed = started.elapsed();
                    if elapsed >= limit {
                        return Err(executor_error(
                            ErrorCode::DeadlineExceeded,
                            format!(
                                "timed out after {} ms waiting for container {} generation {}",
                                request.timeout_ms.unwrap_or_default(),
                                key.id,
                                key.generation
                            ),
                        )
                        .retryable(true));
                    }
                    WAIT_POLL_INTERVAL.min(limit - elapsed)
                }
                None => WAIT_POLL_INTERVAL,
            };
            sleep(delay).await;
        }
    }
}

#[async_trait]
impl GuestAgentService for LinuxExecutor {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        let operation = RecordedRequest::new(MutationKind::Create, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_state(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = self.create_new(&mut state, &request).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::State(result.clone()),
        );
        result
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        let mut state = self.state.lock().await;
        Self::state_new(&mut state, &request)
    }

    async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
        let operation = RecordedRequest::new(MutationKind::Start, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_state(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = Self::start_new(&mut state, &request).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::State(result.clone()),
        );
        result
    }

    async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
        let operation = RecordedRequest::new(MutationKind::Kill, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_state(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = Self::kill_new(&mut state, &request);
        state.record(
            operation_id,
            operation,
            RecordedOutcome::State(result.clone()),
        );
        result
    }

    async fn delete(&self, request: AgentDeleteRequest) -> Result<()> {
        let operation = RecordedRequest::new(MutationKind::Delete, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_unit(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = self.delete_new(&mut state, &request).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::Unit(result.clone()),
        );
        result
    }

    async fn wait(&self, request: AgentWaitRequest) -> Result<ExitStatus> {
        self.wait_new(&request).await
    }

    async fn exec(&self, request: AgentExecRequest) -> Result<AgentProcess> {
        self.exec_recorded(request).await
    }

    async fn signal_process(&self, request: AgentSignalProcessRequest) -> Result<()> {
        self.signal_process_recorded(request).await
    }

    async fn wait_process(&self, request: AgentWaitProcessRequest) -> Result<ExitStatus> {
        self.wait_process_new(&request).await
    }

    async fn pause(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        let operation = RecordedRequest::new(MutationKind::Pause, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_state(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = Self::freezer_new(&mut state, &request, true).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::State(result.clone()),
        );
        result
    }

    async fn resume(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        let operation = RecordedRequest::new(MutationKind::Resume, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_state(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = Self::freezer_new(&mut state, &request, false).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::State(result.clone()),
        );
        result
    }

    async fn processes(&self, request: AgentProcessesRequest) -> Result<Vec<ProcessRecord>> {
        let mut state = self.state.lock().await;
        Self::processes_new(&mut state, &request)
    }

    async fn update(&self, request: AgentUpdateRequest) -> Result<AgentState> {
        let operation = RecordedRequest::new(MutationKind::Update, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_state(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = Self::update_new(&mut state, &request).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::State(result.clone()),
        );
        result
    }

    async fn stats(&self, request: AgentStatsRequest) -> Result<ContainerStats> {
        let mut state = self.state.lock().await;
        Self::stats_new(&mut state, &request).await
    }

    async fn read_output(&self, request: AgentReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.read_output_new(&request).await
    }

    async fn write_stdin(&self, request: AgentWriteStdinRequest) -> Result<()> {
        self.write_stdin_new(&request).await
    }

    async fn close_stdin(&self, request: AgentCloseStdinRequest) -> Result<()> {
        self.close_stdin_new(&request).await
    }
}

async fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).await.map_err(|error| {
        executor_error(
            ErrorCode::Internal,
            format!(
                "failed to create guest container directory {}: {error}",
                path.display()
            ),
        )
    })
}

async fn write_private_snapshot(path: &Path, contents: &str) -> Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).await.map_err(|error| {
        executor_error(
            ErrorCode::Internal,
            format!(
                "failed to create guest configuration snapshot {}: {error}",
                path.display()
            ),
        )
    })?;
    file.write_all(contents.as_bytes()).await.map_err(|error| {
        executor_error(
            ErrorCode::Internal,
            format!(
                "failed to write guest configuration snapshot {}: {error}",
                path.display()
            ),
        )
    })
}

async fn remove_container_directory(root: &Path, directory: &Path) -> Result<()> {
    if directory.parent() != Some(root) || directory == root {
        return Err(executor_error(
            ErrorCode::PermissionDenied,
            format!(
                "refusing to remove guest path outside runtime root: {}",
                directory.display()
            ),
        ));
    }
    match tokio::fs::remove_dir_all(directory).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(executor_error(
            ErrorCode::Internal,
            format!(
                "failed to remove guest container directory {}: {error}",
                directory.display()
            ),
        )),
    }
}

async fn remove_process_directory(container_directory: &Path, directory: &Path) -> Result<()> {
    if directory.parent() != Some(container_directory) || directory == container_directory {
        return Err(executor_error(
            ErrorCode::PermissionDenied,
            format!(
                "refusing to remove guest process path outside its container directory: {}",
                directory.display()
            ),
        ));
    }
    match tokio::fs::remove_dir_all(directory).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(executor_error(
            ErrorCode::Internal,
            format!(
                "failed to remove guest process directory {}: {error}",
                directory.display()
            ),
        )),
    }
}

fn validate_deadline(context: &OperationContext) -> Result<()> {
    let Some(deadline) = context.deadline_unix_ms else {
        return Ok(());
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            executor_error(
                ErrorCode::Internal,
                format!("system clock is before the Unix epoch: {error}"),
            )
        })?
        .as_millis();
    if now >= u128::from(deadline) {
        Err(executor_error(
            ErrorCode::DeadlineExceeded,
            format!("guest operation deadline {deadline} has expired"),
        ))
    } else {
        Ok(())
    }
}

fn executor_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("linux-guest-executor")
}
