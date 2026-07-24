mod control;
mod init;
mod mount;
#[cfg(test)]
mod mount_tests;
mod pid;
mod plan;
#[cfg(test)]
mod plan_tests;
mod process;
mod rootfs;
mod state;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest, AgentStartRequest,
    AgentState, AgentStateRequest, GuestAgentService,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{async_trait, DeleteMode, Error, ErrorCode, OperationContext, Result};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::AGENT_VERSION;
use plan::InitPlan;
use process::PreparedProcess;
use state::{
    ContainerKey, ContainerRecord, ExecutorState, MutationKind, RecordedOutcome, RecordedRequest,
};

pub(crate) use init::run_container_init_if_requested;

const DEFAULT_RUNTIME_PARENT: &str = "/run";
const MAX_OPERATION_RECORDS: usize = 4_096;

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
            capabilities: AgentCapabilities::core(AGENT_VERSION, std::env::consts::ARCH)?,
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
            if let Err(error) = record.process.force_stop().await {
                first_error.get_or_insert(error);
            }
        }
        state.containers.clear();
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
        let process = match PreparedProcess::spawn(&plan, &config_snapshot, &self.init_executable)
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
                process,
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
        record.process.signal(request.signal.get())?;
        record.refresh()?;
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
            if record.status != ContainerState::Stopped {
                if request.mode == DeleteMode::StoppedOnly {
                    return Err(executor_error(
                        ErrorCode::FailedPrecondition,
                        "stopped-only delete requires a stopped container",
                    ));
                }
                record.process.force_stop().await?;
                record.status = ContainerState::Stopped;
            }
            record.runtime_directory.clone()
        };
        remove_container_directory(&self.runtime_root, &runtime_directory).await?;
        state.containers.remove(&key);
        Ok(())
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
        if let Some(result) = state.replay_delete(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = self.delete_new(&mut state, &request).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::Deleted(result.clone()),
        );
        result
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
