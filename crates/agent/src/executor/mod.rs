mod capability;
mod cgroup;
mod control;
mod device;
mod device_mount_transport;
mod device_policy;
mod exec;
mod exec_process;
mod filesystem;
mod hook;
mod inherited_descriptor;
mod init;
mod io;
mod mount;
#[cfg(test)]
mod mount_tests;
mod namespace;
mod pid;
mod pid_supervisor;
#[cfg(test)]
mod pid_supervisor_tests;
mod pidfd;
mod plan;
#[cfg(test)]
mod plan_tests;
mod portable_rootfs_metadata;
mod process;
mod process_group;
#[cfg(test)]
mod process_group_tests;
mod process_io;
mod recovery;
#[cfg(test)]
mod recovery_mode_tests;
mod rlimit;
mod rootfs;
#[cfg(test)]
mod rootfs_tests;
mod seccomp;
#[cfg(test)]
mod seccomp_tests;
mod state;
mod terminal;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCloseStdinRequest, AgentContainerOperationRequest, AgentCreateRequest,
    AgentDeleteRequest, AgentExecRequest, AgentKillRequest, AgentProcess, AgentProcessesRequest,
    AgentReadOutputRequest, AgentRecoveryRecord, AgentResizeRequest, AgentSignalProcessRequest,
    AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest, AgentUpdateRequest,
    AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest, GuestAgentService,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerStats, DeleteMode, Error, ErrorCode, ExitStatus, FileRequest,
    FileResponse, FilesystemRequest, FilesystemResponse, OperationContext, OutputChunk,
    ProcessRecord, Result,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use crate::AGENT_VERSION;
use cgroup::{CgroupManager, RootlessCgroupDelegation};
use hook::HookStateTemplate;
use pidfd::SignalOutcome;
use plan::InitPlan;
use process::{PreparedProcess, ProcessSpawnContext};
use state::{
    ContainerKey, ContainerRecord, ExecutorState, MutationKind, RecordedOutcome, RecordedRequest,
};

pub use inherited_descriptor::InheritedDescriptorPlan;
pub(crate) use pidfd::verify_support as verify_pidfd_support;
pub use recovery::LinuxExecutorTombstone;

/// One-shot rootless device-policy bootstrap completed before Tokio starts.
#[derive(Debug)]
pub struct RootlessDevicePolicyBootstrap {
    delegation: RootlessCgroupDelegation,
    uid: u32,
    gid: u32,
}

impl RootlessDevicePolicyBootstrap {
    /// Retain one exact cgroup delegation, fork its bounded policy helper, and
    /// permanently drop the owner process to its non-root real identity.
    pub fn start(delegated_cgroup_root: impl AsRef<Path>) -> Result<Self> {
        let (uid, gid) = device_policy::DevicePolicyAuthority::bootstrap_identity()?;
        let mut delegation = RootlessCgroupDelegation::open(delegated_cgroup_root, uid, gid)?;
        let authority =
            device_policy::DevicePolicyAuthority::spawn(delegation.open_root_descriptor()?)?;
        if let Err(error) = device_policy::DevicePolicyAuthority::drop_to_identity(uid, gid) {
            let _ = authority.shutdown();
            return Err(error);
        }
        delegation.install_device_policy_authority(authority)?;
        Ok(Self {
            delegation,
            uid,
            gid,
        })
    }

    /// Canonical delegation retained by this bootstrap.
    #[must_use]
    pub fn delegated_cgroup_root(&self) -> &Path {
        self.delegation.root()
    }
}

const DEFAULT_RUNTIME_PARENT: &str = "/run";
const KILL_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_OPERATION_RECORDS: usize = 4_096;
const MAX_INTERNAL_PROCESS_IO_BYTES: usize = 1_024;
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RootfsScope {
    BundleOnly,
    NativeAbsolute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryMode {
    Transient,
    DurableNative,
}

impl RootfsScope {
    const fn internal_argument(self) -> &'static str {
        match self {
            Self::BundleOnly => "bundle-only",
            Self::NativeAbsolute => "native-absolute",
        }
    }

    fn from_internal_argument(value: &OsStr) -> Option<Self> {
        match value.to_str()? {
            "bundle-only" => Some(Self::BundleOnly),
            "native-absolute" => Some(Self::NativeAbsolute),
            _ => None,
        }
    }
}

pub(crate) fn run_container_init_if_requested() -> Option<Result<()>> {
    init::run_container_init_if_requested()
        .or_else(exec_process::run_container_exec_if_requested)
        .or_else(filesystem::run_container_filesystem_if_requested)
}

/// Fail-closed Linux OCI executor shared by native and utility-VM drivers.
#[derive(Debug)]
pub struct LinuxExecutor {
    capabilities: AgentCapabilities,
    init_executable: PathBuf,
    runtime_parent: PathBuf,
    runtime_root: PathBuf,
    owner_identity: Option<recovery::ProcessIdentity>,
    rootfs_scope: RootfsScope,
    user_mapping_runtime: namespace::UserMappingRuntime,
    rootless_cgroup_delegation: Option<RootlessCgroupDelegation>,
    state: Arc<Mutex<ExecutorState>>,
}

impl LinuxExecutor {
    pub(crate) async fn new() -> Result<Self> {
        let executable = std::env::current_exe().map_err(|error| {
            executor_error(
                ErrorCode::Internal,
                format!("failed to resolve guest-agent executable: {error}"),
            )
        })?;
        Self::open_with_rootfs_scope(
            DEFAULT_RUNTIME_PARENT,
            executable,
            RootfsScope::BundleOnly,
            RecoveryMode::Transient,
        )
        .await
    }

    /// Open the transient utility-VM executor inside its mounted writable share.
    pub(crate) async fn new_utility_vm(runtime_parent: impl AsRef<Path>) -> Result<Self> {
        let executable = std::env::current_exe().map_err(|error| {
            executor_error(
                ErrorCode::Internal,
                format!("failed to resolve guest-agent executable: {error}"),
            )
        })?;
        Self::open_with_rootfs_scope(
            runtime_parent,
            executable,
            RootfsScope::BundleOnly,
            RecoveryMode::Transient,
        )
        .await
    }

    /// Open a durable bundle-scoped executor beneath a runtime-owned directory.
    ///
    /// The init executable must enter [`crate::run_internal_container_init`]
    /// before starting its normal application path. Native owner records are
    /// retained for host-process recovery; the utility-VM guest uses its
    /// private transient constructor and authenticated outer recovery handoff.
    pub async fn open(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::open_with_rootfs_scope(
            runtime_parent,
            init_executable,
            RootfsScope::BundleOnly,
            RecoveryMode::DurableNative,
        )
        .await
    }

    /// Open the native Linux executor with OCI absolute root paths enabled.
    ///
    /// This scope is reserved for the explicitly selected shared-host-kernel
    /// driver. Relative root paths remain confined to their bundle, while an
    /// absolute root path may identify a separately managed host directory.
    pub async fn open_native_with_absolute_rootfs(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::open_with_rootfs_scope(
            runtime_parent,
            init_executable,
            RootfsScope::NativeAbsolute,
            RecoveryMode::DurableNative,
        )
        .await
    }

    /// Open the native Linux executor with an explicit rootless cgroup-v2 delegation.
    ///
    /// The path must be a canonical, process-free cgroup-v2 directory owned by
    /// the executor's effective UID/GID. All supported controllers must have
    /// been delegated and enabled by the host before this call.
    pub async fn open_native_with_rootless_cgroup_delegation(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
        delegated_cgroup_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let executor = Self::open_with_rootfs_scope(
            runtime_parent,
            init_executable,
            RootfsScope::NativeAbsolute,
            RecoveryMode::DurableNative,
        )
        .await?;
        executor
            .install_rootless_cgroup_delegation(delegated_cgroup_root)
            .await
    }

    /// Open rootless native Linux with an inherited privileged device-policy authority.
    ///
    /// The constructor retains the verified delegation before the caller
    /// drops privilege, starts one parent-bound helper, and never exposes a
    /// global privileged executable or arbitrary BPF interface.
    pub async fn open_native_with_rootless_cgroup_device_policy(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
        bootstrap: RootlessDevicePolicyBootstrap,
    ) -> Result<Self> {
        let mut executor = Self::open_with_rootfs_scope(
            runtime_parent,
            init_executable,
            RootfsScope::NativeAbsolute,
            RecoveryMode::DurableNative,
        )
        .await?;
        let Some((effective_uid, effective_gid)) = executor.user_mapping_runtime.effective_ids()
        else {
            let _ = tokio::fs::remove_dir_all(&executor.runtime_root).await;
            return Err(executor_error(
                ErrorCode::InvalidArgument,
                "rootless device-policy execution requires a non-root Linux executor",
            ));
        };
        if (effective_uid, effective_gid) != (bootstrap.uid, bootstrap.gid) {
            let _ = tokio::fs::remove_dir_all(&executor.runtime_root).await;
            return Err(executor_error(
                ErrorCode::Conflict,
                "rootless device-policy executor identity differs from its synchronous bootstrap",
            ));
        }
        if let Err(error) = bootstrap.delegation.verify() {
            let _ = tokio::fs::remove_dir_all(&executor.runtime_root).await;
            return Err(error);
        }
        executor.rootless_cgroup_delegation = Some(bootstrap.delegation);
        Ok(executor)
    }

    async fn install_rootless_cgroup_delegation(
        mut self,
        delegated_cgroup_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let Some((effective_uid, effective_gid)) = self.user_mapping_runtime.effective_ids() else {
            let _ = tokio::fs::remove_dir_all(&self.runtime_root).await;
            return Err(executor_error(
                ErrorCode::InvalidArgument,
                "rootless cgroup delegation requires a non-root Linux executor",
            ));
        };
        let delegation = match RootlessCgroupDelegation::open(
            delegated_cgroup_root,
            effective_uid,
            effective_gid,
        ) {
            Ok(delegation) => delegation,
            Err(error) => {
                let _ = tokio::fs::remove_dir_all(&self.runtime_root).await;
                return Err(error);
            }
        };
        self.rootless_cgroup_delegation = Some(delegation);
        Ok(self)
    }

    async fn open_with_rootfs_scope(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
        rootfs_scope: RootfsScope,
        recovery_mode: RecoveryMode,
    ) -> Result<Self> {
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
        let user_mapping_runtime = namespace::UserMappingRuntime::detect()?;
        let runtime_parent = parent.to_path_buf();
        let (runtime_root, owner_identity) =
            executor_runtime_layout(&runtime_parent, recovery_mode)?;
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

        if let Some(owner) = owner_identity {
            if let Err(error) = recovery::write_owner_record(&runtime_root, owner).await {
                let _ = tokio::fs::remove_dir_all(&runtime_root).await;
                return Err(error);
            }
        }

        Ok(Self {
            capabilities: AgentCapabilities::linux_executor(AGENT_VERSION, std::env::consts::ARCH)?,
            init_executable,
            runtime_parent,
            runtime_root,
            owner_identity,
            rootfs_scope,
            user_mapping_runtime,
            rootless_cgroup_delegation: None,
            state: Arc::new(Mutex::new(ExecutorState::default())),
        })
    }

    /// Absolute private directory holding this executor's transient state.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Stop every owned init process and remove all transient executor state.
    pub async fn shutdown(&self) -> Result<()> {
        self.shutdown_with_recovery().await.map(drop)
    }

    /// Stop every owned process and retain exact init terminal evidence.
    ///
    /// Evidence is returned only when the complete executor cleanup succeeds.
    /// Callers must not persist a partial vector from a failed cleanup.
    pub async fn shutdown_with_recovery(&self) -> Result<Vec<AgentRecoveryRecord>> {
        let mut state = self.state.lock().await;
        let mut first_error = None;
        let mut poststop = Vec::new();
        let mut recovery = Vec::with_capacity(state.containers.len());
        for record in state.containers.values_mut() {
            if let Err(error) = record.force_stop_all().await {
                first_error.get_or_insert(error);
            } else {
                match record.recovery_record() {
                    Ok(record) => recovery.push(record),
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            poststop.push(record.process.poststop_plan());
        }
        state.containers.clear();
        let cgroup_manager = state.cgroup_manager.take();
        if let Some(delegation) = &self.rootless_cgroup_delegation {
            if let Err(error) = delegation.shutdown_device_policy_authority() {
                first_error.get_or_insert(error);
            }
        }
        if let Some(manager) = cgroup_manager {
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
        for plan in poststop {
            match plan {
                Ok((hooks, hook_state)) => hooks.run_poststop(&hook_state).await,
                Err(error) => {
                    eprintln!("a3s-oci-agent: shutdown poststop hook state warning: {error}");
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(recovery),
        }
    }

    async fn create_new(
        &self,
        state: &mut ExecutorState,
        request: &AgentCreateRequest,
        inherited_descriptors: InheritedDescriptorPlan,
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
        if self.user_mapping_runtime.is_rootless() {
            if !plan.namespaces.new_user() {
                return Err(executor_error(
                    ErrorCode::Unsupported,
                    "rootless native execution requires a newly created user namespace",
                ));
            }
            if !plan.additional_gids.is_empty() {
                return Err(executor_error(
                    ErrorCode::Unsupported,
                    "rootless native execution cannot apply process.user.additionalGids after setgroups=deny",
                ));
            }
            if plan.cgroup.has_cgroup() && self.rootless_cgroup_delegation.is_none() {
                return Err(executor_error(
                    ErrorCode::Unsupported,
                    "rootless linux.cgroupsPath requires an explicit verified cgroup-v2 delegation",
                ));
            }
            if plan.devices.has_access_policy()
                && self
                    .rootless_cgroup_delegation
                    .as_ref()
                    .is_none_or(|delegation| !delegation.has_device_policy_authority())
            {
                return Err(executor_error(
                    ErrorCode::Unsupported,
                    "rootless linux.devices and linux.resources.devices require an authenticated delegated-cgroup device-policy authority",
                ));
            }
            if self
                .rootless_cgroup_delegation
                .as_ref()
                .is_some_and(RootlessCgroupDelegation::has_device_policy_authority)
            {
                plan.devices.validate_rootless_device_set()?;
            }
        }
        let hook_state = HookStateTemplate::new(
            plan.oci_version.clone(),
            key.id.clone(),
            plan.bundle_directory.clone(),
            plan.annotations.clone(),
        )?;
        if plan.cgroup.has_cgroup() && state.cgroup_manager.is_none() {
            state.cgroup_manager = Some(match &self.rootless_cgroup_delegation {
                Some(delegation) => CgroupManager::create_delegated(delegation)?,
                None => CgroupManager::create()?,
            });
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
        let rootless_device_mounts =
            if self.user_mapping_runtime.is_rootless() && plan.devices.has_node_setup() {
                match self
                    .rootless_cgroup_delegation
                    .as_ref()
                    .ok_or_else(|| {
                        executor_error(
                        ErrorCode::Internal,
                        "rootless device-policy delegation disappeared before mount preparation",
                    )
                    })
                    .and_then(RootlessCgroupDelegation::prepare_device_mounts)
                {
                    Ok(mounts) => mounts,
                    Err(error) => {
                        let _ = remove_container_directory(&self.runtime_root, &runtime_directory)
                            .await;
                        return Err(error);
                    }
                }
            } else {
                Vec::new()
            };
        let mut process = match PreparedProcess::spawn(
            &plan,
            &config_snapshot,
            &self.init_executable,
            state.cgroup_manager.as_ref(),
            &request.io,
            &hook_state,
            ProcessSpawnContext {
                inherited_descriptors,
                rootless_device_mounts,
                rootfs_scope: self.rootfs_scope,
                user_mapping_runtime: &self.user_mapping_runtime,
            },
        )
        .await
        {
            Ok(process) => process,
            Err(error) => {
                if cleanup_device_targets(&runtime_directory).is_ok() {
                    let _ =
                        remove_container_directory(&self.runtime_root, &runtime_directory).await;
                }
                return Err(error);
            }
        };
        if let Some(owner) = self.owner_identity {
            if let Err(error) = recovery::write_container_record(
                &runtime_directory,
                &config_snapshot,
                &request.target,
                request.bundle.config_digest(),
                owner,
                &process,
                state.cgroup_manager.as_ref(),
            )
            .await
            {
                let _ = process.force_stop().await;
                if cleanup_device_targets(&runtime_directory).is_ok() {
                    let _ =
                        remove_container_directory(&self.runtime_root, &runtime_directory).await;
                }
                return Err(error);
            }
        }
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

    /// Reconcile one durable generation left by a terminated executor owner.
    ///
    /// The returned tombstone proves that the exact recorded launcher and init
    /// identities have disappeared. It retains only the paths required for a
    /// later stopped-only delete; no live process handle is reconstructed.
    pub async fn recover_stale_generation(
        &self,
        target: &a3s_oci_sdk::ContainerTarget,
        config_digest: &str,
        durable_pid: Option<i32>,
    ) -> Result<Option<LinuxExecutorTombstone>> {
        if self.owner_identity.is_none() {
            return Err(executor_error(
                ErrorCode::Unsupported,
                "stale-generation recovery is available only for durable native Linux executors",
            ));
        }
        recovery::recover_stale_generation(
            &self.runtime_parent,
            &self.runtime_root,
            target,
            config_digest,
            durable_pid,
        )
        .await
    }

    /// Remove the exact transient paths retained by a recovered tombstone.
    pub async fn delete_stale_generation(&self, tombstone: &LinuxExecutorTombstone) -> Result<()> {
        recovery::delete_stale_generation(tombstone).await
    }

    /// Create through the native in-process path with validated inherited
    /// workload descriptors. Raw descriptors never enter an agent frame.
    pub async fn create_with_inherited_descriptors(
        &self,
        request: AgentCreateRequest,
        inherited_descriptors: InheritedDescriptorPlan,
    ) -> Result<AgentState> {
        let operation = RecordedRequest::create(&request, inherited_descriptors.schema())?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_state(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = self
            .create_new(&mut state, &request, inherited_descriptors)
            .await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::State(result.clone()),
        );
        result
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
        if let Err(error) = record.process.release().await {
            record.status = ContainerState::Stopped;
            return Err(error);
        }
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

    async fn kill_new(state: &mut ExecutorState, request: &AgentKillRequest) -> Result<AgentState> {
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
        if record.status == ContainerState::Stopped {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                "cannot signal a stopped container",
            ));
        }
        let outcome = if request.all {
            record.signal_all(request.signal.get())?
        } else {
            record.process.signal(request.signal.get())?
        };
        match outcome {
            SignalOutcome::Delivered if confirms_terminal_kill(request.signal) => {
                let deadline = Instant::now() + KILL_CONFIRM_TIMEOUT;
                loop {
                    record.refresh()?;
                    if record.status == ContainerState::Stopped || Instant::now() >= deadline {
                        break;
                    }
                    sleep(WAIT_POLL_INTERVAL).await;
                }
            }
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
        let (runtime_directory, poststop) = {
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
            (
                record.runtime_directory.clone(),
                record.process.poststop_plan(),
            )
        };
        cleanup_device_targets(&runtime_directory)?;
        remove_container_directory(&self.runtime_root, &runtime_directory).await?;
        state.containers.remove(&key);
        match poststop {
            Ok((hooks, hook_state)) => hooks.run_poststop(&hook_state).await,
            Err(error) => eprintln!("a3s-oci-agent: poststop hook state warning: {error}"),
        }
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
        self.create_with_inherited_descriptors(request, InheritedDescriptorPlan::empty())
            .await
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
        let result = Self::kill_new(&mut state, &request).await;
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
        self.write_stdin_recorded(request).await
    }

    async fn close_stdin(&self, request: AgentCloseStdinRequest) -> Result<()> {
        self.close_stdin_recorded(request).await
    }

    async fn resize(&self, request: AgentResizeRequest) -> Result<()> {
        self.resize_recorded(request).await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.file_recorded(request).await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.filesystem_recorded(request).await
    }
}

fn confirms_terminal_kill(signal: a3s_oci_sdk::Signal) -> bool {
    signal.get() == libc::SIGKILL
}

fn executor_runtime_layout(
    runtime_parent: &Path,
    recovery_mode: RecoveryMode,
) -> Result<(PathBuf, Option<recovery::ProcessIdentity>)> {
    let owner_identity = match recovery_mode {
        RecoveryMode::Transient => None,
        RecoveryMode::DurableNative => Some(recovery::ProcessIdentity::current()?),
    };
    let name = match owner_identity {
        Some(owner) => recovery::runtime_root_name(owner),
        None => recovery::transient_runtime_root_name(std::process::id()),
    };
    Ok((runtime_parent.join(name), owner_identity))
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

fn cleanup_device_targets(runtime_directory: &Path) -> Result<()> {
    let Some(manifest) = device::load_device_target_manifest(runtime_directory)? else {
        return Ok(());
    };
    device::cleanup_device_target_manifest(&manifest)
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

#[cfg(test)]
mod kill_tests {
    use a3s_oci_sdk::Signal;

    use super::confirms_terminal_kill;

    #[test]
    fn only_sigkill_requires_bounded_terminal_confirmation() {
        assert!(confirms_terminal_kill(
            Signal::new(libc::SIGKILL).expect("SIGKILL")
        ));
        assert!(!confirms_terminal_kill(
            Signal::new(libc::SIGTERM).expect("SIGTERM")
        ));
    }
}

#[cfg(test)]
mod rootless_device_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use a3s_oci_agent_protocol::{AgentBundle, AgentCreateRequest, GuestPath};
    use a3s_oci_sdk::OciBundle;
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, ErrorCode, Generation, IoMode, OperationContext, OperationId,
        ProcessIo,
    };
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    use super::{
        namespace, AgentCapabilities, ExecutorState, InheritedDescriptorPlan, LinuxExecutor,
    };

    #[tokio::test]
    async fn rejects_device_setup_while_rootless() {
        let tempdir = TempDir::new().expect("temp dir");
        let bundle_directory = tempdir.path().join("bundle");
        fs::create_dir_all(&bundle_directory).expect("bundle dir");
        let runtime_parent = tempdir.path().join("runtime-parent");
        let runtime_root = runtime_parent.join("runtime-root");
        fs::create_dir_all(&runtime_root).expect("runtime root");

        let config = json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs", "readonly": false},
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/sh", "-c", "printf ready"],
                "env": ["PATH=/bin:/usr/bin"],
                "cwd": "/",
                "noNewPrivileges": true
            },
            "linux": {
                "namespaces": [
                    {"type": "user"},
                    {"type": "mount"}
                ],
                "uidMappings": [
                    {"containerID": 0, "hostID": 1000, "size": 1}
                ],
                "gidMappings": [
                    {"containerID": 0, "hostID": 1001, "size": 1}
                ],
                "resources": {
                    "devices": [
                        {"allow": false, "access": "rwm"}
                    ]
                }
            }
        });
        let config = serde_json::to_string(&config).expect("encode rootless device config");
        let bundle = OciBundle::from_json(bundle_directory.clone(), config).expect("OCI bundle");
        let request = AgentCreateRequest {
            context: OperationContext::new(
                OperationId::new("rootless-device-create").expect("operation id"),
            ),
            target: ContainerTarget::exact(
                ContainerId::new("rootless-device").expect("container id"),
                Generation(1),
            ),
            bundle: AgentBundle::new(
                &bundle,
                GuestPath::new(bundle_directory.to_string_lossy().into_owned())
                    .expect("guest bundle directory"),
            ),
            io: ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Null,
                stderr: IoMode::Null,
                terminal_size: None,
            },
        };
        let executor = LinuxExecutor {
            capabilities: AgentCapabilities::handshake_only("test", "x86_64")
                .expect("capabilities"),
            init_executable: std::env::current_exe().expect("test executable"),
            runtime_parent,
            runtime_root,
            owner_identity: None,
            rootfs_scope: super::RootfsScope::BundleOnly,
            user_mapping_runtime: namespace::UserMappingRuntime::Rootless {
                effective_uid: 1000,
                effective_gid: 1001,
                newuidmap: PathBuf::from("/usr/bin/newuidmap"),
                newgidmap: PathBuf::from("/usr/bin/newgidmap"),
            },
            rootless_cgroup_delegation: None,
            state: Arc::new(Mutex::new(ExecutorState::default())),
        };

        let error = executor
            .create_with_inherited_descriptors(request, InheritedDescriptorPlan::empty())
            .await
            .expect_err("rootless device setup must fail closed");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error
            .message
            .contains("linux.devices and linux.resources.devices"));
    }

    #[tokio::test]
    async fn rejects_cgroup_path_without_explicit_rootless_delegation() {
        let tempdir = TempDir::new().expect("temp dir");
        let bundle_directory = tempdir.path().join("bundle");
        fs::create_dir_all(&bundle_directory).expect("bundle dir");
        let runtime_parent = tempdir.path().join("runtime-parent");
        let runtime_root = runtime_parent.join("runtime-root");
        fs::create_dir_all(&runtime_root).expect("runtime root");

        let config = json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs", "readonly": false},
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/sh", "-c", "printf ready"],
                "env": ["PATH=/bin:/usr/bin"],
                "cwd": "/",
                "noNewPrivileges": true
            },
            "linux": {
                "namespaces": [
                    {"type": "user"},
                    {"type": "mount"}
                ],
                "uidMappings": [
                    {"containerID": 0, "hostID": 1000, "size": 1}
                ],
                "gidMappings": [
                    {"containerID": 0, "hostID": 1001, "size": 1}
                ],
                "cgroupsPath": "a3s/rootless-cgroup"
            }
        });
        let config = serde_json::to_string(&config).expect("encode rootless cgroup config");
        let bundle = OciBundle::from_json(bundle_directory.clone(), config).expect("OCI bundle");
        let request = AgentCreateRequest {
            context: OperationContext::new(
                OperationId::new("rootless-cgroup-create").expect("operation id"),
            ),
            target: ContainerTarget::exact(
                ContainerId::new("rootless-cgroup").expect("container id"),
                Generation(1),
            ),
            bundle: AgentBundle::new(
                &bundle,
                GuestPath::new(bundle_directory.to_string_lossy().into_owned())
                    .expect("guest bundle directory"),
            ),
            io: ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Null,
                stderr: IoMode::Null,
                terminal_size: None,
            },
        };
        let executor = LinuxExecutor {
            capabilities: AgentCapabilities::handshake_only("test", "x86_64")
                .expect("capabilities"),
            init_executable: std::env::current_exe().expect("test executable"),
            runtime_parent,
            runtime_root,
            owner_identity: None,
            rootfs_scope: super::RootfsScope::BundleOnly,
            user_mapping_runtime: namespace::UserMappingRuntime::Rootless {
                effective_uid: 1000,
                effective_gid: 1001,
                newuidmap: PathBuf::from("/usr/bin/newuidmap"),
                newgidmap: PathBuf::from("/usr/bin/newgidmap"),
            },
            rootless_cgroup_delegation: None,
            state: Arc::new(Mutex::new(ExecutorState::default())),
        };

        let error = executor
            .create_with_inherited_descriptors(request, InheritedDescriptorPlan::empty())
            .await
            .expect_err("missing rootless cgroup delegation must fail closed");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error
            .message
            .contains("requires an explicit verified cgroup-v2 delegation"));
    }
}
