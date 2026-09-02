use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{AgentCreateRequest, AgentState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{async_trait, Error, ErrorCode, IoMode, Result};
use tokio::process::{Child, Command};

use super::cgroup::{self, CgroupManager};
use super::hook::HookStateTemplate;
use super::plan::InitPlan;
use super::process::PreparedProcess;
use super::state::{ContainerKey, ContainerRecord};
use super::{
    cleanup_device_targets, create_private_directory, mount, remove_container_directory,
    validate_deadline, write_private_snapshot, LinuxExecutor, RootfsScope,
};

/// Runtime-owned CRIU spawn boundary used by the native Linux executor.
#[async_trait]
pub trait LinuxRestoreSpawner: Send + Sync {
    /// Spawn one restore supervisor. The returned child must become the direct
    /// parent of the restored init before it reports readiness.
    async fn spawn(&self, request: LinuxRestoreSpawnRequest) -> Result<Child>;
}

/// Exact executor resources supplied to one native restore spawner.
#[derive(Debug)]
pub struct LinuxRestoreSpawnRequest {
    pub(super) supervisor_executable: PathBuf,
    pub(super) config_snapshot: PathBuf,
    pub(super) control_name: String,
    pub(super) expected_owner_pid: i32,
    pub(super) rootfs: PathBuf,
    pub(super) cgroup_namespace: File,
    pub(super) control_cgroup_procs: File,
    pub(super) external_mounts: Vec<RestoreExternalMount>,
}

#[derive(Debug)]
pub(super) struct RestoreExternalMount {
    name: String,
    mountpoint: PathBuf,
    source: PathBuf,
}

impl RestoreExternalMount {
    fn new(name: String, mountpoint: PathBuf, source: PathBuf) -> Self {
        Self {
            name,
            mountpoint,
            source,
        }
    }
}

impl LinuxRestoreSpawnRequest {
    #[must_use]
    pub fn supervisor_executable(&self) -> &Path {
        &self.supervisor_executable
    }

    #[must_use]
    pub fn config_snapshot(&self) -> &Path {
        &self.config_snapshot
    }

    #[must_use]
    pub fn control_name(&self) -> &str {
        &self.control_name
    }

    #[must_use]
    pub const fn expected_owner_pid(&self) -> i32 {
        self.expected_owner_pid
    }

    #[must_use]
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    /// Stable cookie, container mountpoint, and newly prepared host source for
    /// each explicit external device mount.
    pub fn external_mounts(&self) -> impl Iterator<Item = (&str, &Path, &Path)> {
        self.external_mounts.iter().map(|mount| {
            (
                mount.name.as_str(),
                mount.mountpoint.as_path(),
                mount.source.as_path(),
            )
        })
    }

    /// Install the parent-death and cgroup-control boundary on a CRIU command.
    pub fn prepare_command(&self, command: &mut Command) -> Result<()> {
        let control_cgroup_procs = self.control_cgroup_procs.try_clone().map_err(|error| {
            restore_error(
                ErrorCode::Internal,
                format!("failed to clone restore control cgroup descriptor: {error}"),
            )
        })?;
        let cgroup_namespace = self.cgroup_namespace.try_clone().map_err(|error| {
            restore_error(
                ErrorCode::Internal,
                format!("failed to clone restore cgroup namespace descriptor: {error}"),
            )
        })?;
        let expected_owner_pid = self.expected_owner_pid;
        // SAFETY: the callback executes before CRIU in the freshly forked
        // child. It performs only the existing bounded parent-death check and
        // one write through a retained cgroup.procs descriptor.
        unsafe {
            command.pre_exec(move || {
                super::fd_boundary::mark_private_descriptors_close_on_exec()?;
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                super::pid_supervisor::verify_and_arm_parent_death_signal(
                    expected_owner_pid,
                    "CRIU restore launcher",
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
                cgroup::join_current_process(std::os::fd::AsRawFd::as_raw_fd(
                    &control_cgroup_procs,
                ))?;
                // SAFETY: this is a retained cgroup namespace descriptor
                // created for the exact target envelope.
                if libc::setns(
                    std::os::fd::AsRawFd::as_raw_fd(&cgroup_namespace),
                    libc::CLONE_NEWCGROUP,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

impl LinuxExecutor {
    /// Restore one exact rootful native generation directly into executor
    /// ownership. Successful return is always `running` and cgroup-paused.
    pub async fn restore_with(
        &self,
        request: AgentCreateRequest,
        spawner: &dyn LinuxRestoreSpawner,
    ) -> Result<AgentState> {
        validate_deadline(&request.context)?;
        if self.rootfs_scope != RootfsScope::NativeAbsolute
            || self.user_mapping_runtime.is_rootless()
            || self.vm_attachments.is_some()
        {
            return Err(restore_error(
                ErrorCode::Unsupported,
                "CRIU restore v1 requires the rootful native Linux executor",
            ));
        }
        let key = ContainerKey::from_target(&request.target)?;
        let mut state = self.state.lock().await;
        if let Some(record) = state.containers.get_mut(&key) {
            record.refresh()?;
            if record.target == request.target
                && record.config_digest == request.bundle.config_digest()
                && record.status == ContainerState::Running
                && record.paused
            {
                return record.state();
            }
            return Err(restore_error(
                ErrorCode::Conflict,
                "restore target already exists with different live state",
            ));
        }
        if state
            .containers
            .keys()
            .any(|candidate| candidate.id == key.id)
        {
            return Err(restore_error(
                ErrorCode::AlreadyExists,
                format!("container {} already exists in the executor", key.id),
            ));
        }
        if state
            .highest_generations
            .get(&key.id)
            .is_some_and(|generation| key.generation <= *generation)
        {
            return Err(restore_error(
                ErrorCode::Conflict,
                format!(
                    "container {} generation {} is not newer than the executor fence",
                    key.id, key.generation
                ),
            ));
        }

        let bundle = request.bundle.to_guest_bundle()?;
        let process_io = match bundle.spec().process().as_ref() {
            Some(process) => request.io.resolve_for_process(process)?,
            None => request.io.clone(),
        };
        require_null_io(&process_io)?;
        let vm_storage_sources = crate::vm_attachment::UtilityVmStorageSources::default();
        let mut plan = InitPlan::from_bundle(&bundle, &process_io)?;
        mount::rewrite_vm_storage_sources(&mut plan.mounts, &vm_storage_sources)?;
        mount::validate_bundle_source_syntax(&plan.mounts, self.rootfs_scope)?;
        plan.cgroup.ensure_runtime_path(&key.id, key.generation)?;
        plan.resolve_cgroup_ownership(None)?;
        require_restore_v1_plan(&plan)?;
        let hook_state = HookStateTemplate::new(
            plan.oci_version.clone(),
            key.id.clone(),
            plan.bundle_directory.clone(),
            plan.annotations.clone(),
        )?;
        if state.cgroup_manager.is_none() {
            state.cgroup_manager = Some(CgroupManager::create()?);
        }

        let slot = state.next_slot.checked_add(1).ok_or_else(|| {
            restore_error(
                ErrorCode::ResourceExhausted,
                "executor container slot space is exhausted",
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
        if let Err(error) = plan
            .devices
            .prepare_restore_targets(&plan.rootfs, &runtime_directory)
        {
            if cleanup_device_targets(&runtime_directory).is_ok() {
                let _ = remove_container_directory(&self.runtime_root, &runtime_directory).await;
            }
            return Err(error);
        }
        let external_mounts = match plan
            .devices
            .prepare_restore_external_mounts(&plan.namespaces, &runtime_directory)
        {
            Ok(mounts) => mounts
                .into_iter()
                .map(|(name, mountpoint, source)| {
                    RestoreExternalMount::new(name, mountpoint, source)
                })
                .collect(),
            Err(error) => {
                if cleanup_device_targets(&runtime_directory).is_ok() {
                    let _ =
                        remove_container_directory(&self.runtime_root, &runtime_directory).await;
                }
                return Err(error);
            }
        };

        let mut process = match PreparedProcess::restore(
            &plan,
            &config_snapshot,
            &self.init_executable,
            state.cgroup_manager.as_ref(),
            &hook_state,
            external_mounts,
            spawner,
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
            if let Err(error) = super::recovery::write_container_record(
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
        let response = match AgentState::new_with_pause(
            request.target.clone(),
            ContainerState::Running,
            Some(process.pid()),
            request.bundle.config_digest(),
            true,
        ) {
            Ok(response) => response,
            Err(error) => {
                let _ = process.force_stop().await;
                if cleanup_device_targets(&runtime_directory).is_ok() {
                    let _ =
                        remove_container_directory(&self.runtime_root, &runtime_directory).await;
                }
                return Err(error);
            }
        };
        state
            .highest_generations
            .insert(key.id.clone(), key.generation);
        state.containers.insert(
            key,
            ContainerRecord {
                target: request.target,
                config_digest: request.bundle.config_digest().to_string(),
                status: ContainerState::Running,
                paused: true,
                process,
                processes: std::collections::BTreeMap::new(),
                runtime_directory,
            },
        );
        Ok(response)
    }

    /// Remove a generation created by a restore attempt that could not durably
    /// retain its driver outcome.
    pub async fn rollback_restore(
        &self,
        target: &a3s_oci_sdk::ContainerTarget,
        config_digest: &str,
    ) -> Result<()> {
        let key = ContainerKey::from_target(target)?;
        let mut state = self.state.lock().await;
        let Some(record) = state.containers.get_mut(&key) else {
            return Ok(());
        };
        if &record.target != target || record.config_digest != config_digest {
            return Err(restore_error(
                ErrorCode::Conflict,
                "refusing to roll back a restore generation with different identity",
            ));
        }
        record.force_stop_all().await?;
        record.process.cleanup_intel_rdt()?;
        let runtime_directory = record.runtime_directory.clone();
        cleanup_device_targets(&runtime_directory)?;
        remove_container_directory(&self.runtime_root, &runtime_directory).await?;
        state.containers.remove(&key);
        Ok(())
    }
}

pub(super) struct RestoreRootfsMount {
    path: PathBuf,
    active: bool,
}

impl RestoreRootfsMount {
    pub(super) fn bind(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            restore_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect restore rootfs {}: {error}",
                    path.display()
                ),
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(restore_error(
                ErrorCode::FailedPrecondition,
                format!("restore rootfs is not a real directory: {}", path.display()),
            ));
        }
        let encoded = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            restore_error(
                ErrorCode::InvalidArgument,
                format!("restore rootfs path contains NUL: {}", path.display()),
            )
        })?;
        // SAFETY: both pointers reference the same live NUL-terminated path;
        // a self bind creates one removable mount layer without changing data.
        if unsafe {
            libc::mount(
                encoded.as_ptr(),
                encoded.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(restore_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to make restore rootfs {} a mount point: {}",
                    path.display(),
                    io::Error::last_os_error()
                ),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            active: true,
        })
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let encoded = CString::new(self.path.as_os_str().as_bytes()).map_err(|_| {
            restore_error(
                ErrorCode::Internal,
                "retained restore rootfs path contains NUL",
            )
        })?;
        // SAFETY: this removes only the self-bind layer created by `bind`.
        if unsafe { libc::umount2(encoded.as_ptr(), 0) } != 0 {
            return Err(restore_error(
                ErrorCode::Internal,
                format!(
                    "failed to release restore rootfs mount {}: {}",
                    self.path.display(),
                    io::Error::last_os_error()
                ),
            ));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for RestoreRootfsMount {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn require_null_io(io: &a3s_oci_sdk::ProcessIo) -> Result<()> {
    if io.stdin == IoMode::Null
        && io.stdout == IoMode::Null
        && io.stderr == IoMode::Null
        && io.terminal_size.is_none()
    {
        Ok(())
    } else {
        Err(restore_error(
            ErrorCode::Unsupported,
            "CRIU restore format v1 requires null init stdin, stdout, and stderr",
        ))
    }
}

fn require_restore_v1_plan(plan: &InitPlan) -> Result<()> {
    if plan.namespaces.new_pid()
        || plan.namespaces.joined_pid().is_some()
        || plan.namespaces.has_user()
        || plan.namespaces.has_network()
        || plan.namespaces.joined_uts().is_some()
        || plan.namespaces.joined_mount().is_some()
        || plan.namespaces.joined_ipc().is_some()
        || plan.namespaces.joined_cgroup().is_some()
        || plan.namespaces.joined_time().is_some()
        || !plan.cgroup.uses_control_workload_layout()
        || plan.terminal
        || plan.intel_rdt.is_some()
        || !plan.network_devices.is_empty()
        || plan.hooks != Default::default()
    {
        return Err(restore_error(
            ErrorCode::Unsupported,
            "CRIU restore format v1 requires no PID, user, or network namespace, only newly created UTS/mount/IPC/cgroup/time namespaces, control-workload-v1 cgroups, null non-terminal I/O, no Intel RDT, no network devices, and no OCI hooks",
        ));
    }
    Ok(())
}

fn restore_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("restore-native-container")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ErrorCode, IoMode, OciBundle, ProcessIo};

    use super::{require_restore_v1_plan, InitPlan};

    fn qualified_config() -> serde_json::Value {
        serde_json::json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs", "readonly": false},
            "mounts": [{
                "destination": "/sys/fs/cgroup",
                "type": "cgroup",
                "source": "cgroup",
                "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]
            }],
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/sh", "-c", "while :; do sleep 1; done"],
                "cwd": "/",
                "noNewPrivileges": true
            },
            "annotations": {
                "dev.a3s.oci.cgroup.layout": "control-workload-v1",
                "dev.a3s.oci.cgroup.control-memory-headroom-bytes": "67108864",
                "dev.a3s.oci.cgroup.control-cpu-headroom-micros": "25000",
                "dev.a3s.oci.cgroup.control-pids-headroom": "16"
            },
            "linux": {
                "cgroupsPath": "restore-profile-test",
                "resources": {
                    "memory": {"limit": 268435456},
                    "cpu": {"quota": 100000, "period": 100000},
                    "pids": {"limit": 64}
                },
                "namespaces": [
                    {"type": "mount"},
                    {"type": "ipc"},
                    {"type": "uts"},
                    {"type": "cgroup"},
                    {"type": "time"}
                ]
            }
        })
    }

    fn plan(config: serde_json::Value) -> InitPlan {
        let bundle = OciBundle::from_json(
            std::env::current_dir()
                .expect("current test directory")
                .join("restore-profile-test-bundle"),
            serde_json::to_string(&config).expect("encode restore profile"),
        )
        .expect("schema-valid restore profile");
        InitPlan::from_bundle(
            &bundle,
            &ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Null,
                stderr: IoMode::Null,
                terminal_size: None,
            },
        )
        .expect("plan restore profile")
    }

    #[test]
    fn accepts_only_the_qualified_restore_v1_namespace_and_io_profile() {
        require_restore_v1_plan(&plan(qualified_config())).expect("qualified restore profile");

        let mut terminal = plan(qualified_config());
        terminal.terminal = true;
        assert_eq!(
            require_restore_v1_plan(&terminal)
                .expect_err("terminal restore must fail closed")
                .code,
            ErrorCode::Unsupported
        );

        let mut user = qualified_config();
        user["linux"]["namespaces"]
            .as_array_mut()
            .expect("namespace array")
            .push(serde_json::json!({"type": "user"}));
        user["linux"]["uidMappings"] =
            serde_json::json!([{"containerID": 0, "hostID": 100000, "size": 65536}]);
        user["linux"]["gidMappings"] =
            serde_json::json!([{"containerID": 0, "hostID": 200000, "size": 65536}]);
        assert_eq!(
            require_restore_v1_plan(&plan(user))
                .expect_err("user namespace restore must fail closed")
                .code,
            ErrorCode::Unsupported
        );

        let mut joined = qualified_config();
        joined["linux"]["namespaces"]
            .as_array_mut()
            .expect("namespace array")
            .retain(|namespace| namespace["type"] != "uts");
        joined["linux"]["namespaces"]
            .as_array_mut()
            .expect("namespace array")
            .push(serde_json::json!({"type": "uts", "path": "/proc/self/ns/uts"}));
        assert_eq!(
            require_restore_v1_plan(&plan(joined))
                .expect_err("joined namespace restore must fail closed")
                .code,
            ErrorCode::Unsupported
        );
    }
}
