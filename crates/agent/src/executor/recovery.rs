use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, Instant};

use super::cgroup::CgroupManager;
use super::device::{cleanup_device_target_manifest, load_device_target_manifest};
use super::intel_rdt::{is_resctrl_mountpoint, IntelRdtRecovery};
use super::process::PreparedProcess;

const RUNTIME_ROOT_PREFIX: &str = "a3s-oci-agent-";
const OWNER_RECORD_NAME: &str = "owner.json";
const CONTAINER_RECORD_NAME: &str = "recovery.json";
const CONFIG_SNAPSHOT_NAME: &str = "config.json";
const OWNER_SCHEMA_VERSION: &str = "a3s.oci.native-linux-executor-owner.v1";
const CONTAINER_SCHEMA_VERSION: &str = "a3s.oci.native-linux-recovery.v3";
const CONTAINER_SCHEMA_VERSION_V2: &str = "a3s.oci.native-linux-recovery.v2";
const CONTAINER_SCHEMA_VERSION_V1: &str = "a3s.oci.native-linux-recovery.v1";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(10);
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProcessIdentity {
    pid: i32,
    start_time_ticks: u64,
}

impl ProcessIdentity {
    pub(super) fn current() -> Result<Self> {
        let raw = std::process::id();
        let pid = i32::try_from(raw).map_err(|error| {
            recovery_error(
                ErrorCode::ResourceExhausted,
                format!("executor owner PID {raw} does not fit the recovery model: {error}"),
            )
        })?;
        Self::capture(pid, "executor owner")
    }

    fn capture(pid: i32, role: &str) -> Result<Self> {
        let observation = process_observation(pid)?
            .filter(|observation| !observation.is_terminated())
            .ok_or_else(|| {
                recovery_error(
                    ErrorCode::Unavailable,
                    format!("{role} PID {pid} exited before its recovery identity was captured"),
                )
                .retryable(true)
            })?;
        Ok(Self {
            pid,
            start_time_ticks: observation.start_time_ticks,
        })
    }

    fn is_live(self) -> Result<bool> {
        Ok(process_observation(self.pid)?.is_some_and(|observation| {
            observation.start_time_ticks == self.start_time_ticks && !observation.is_terminated()
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessObservation {
    start_time_ticks: u64,
    state: u8,
}

impl ProcessObservation {
    const fn is_terminated(self) -> bool {
        matches!(self.state, b'Z' | b'X' | b'x')
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutorOwnerRecord {
    schema_version: String,
    owner: ProcessIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryCgroupRecord {
    authority_root: PathBuf,
    manager_root: PathBuf,
    leaf: PathBuf,
    created: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyRecoveryCgroupRecord {
    manager_root: PathBuf,
    leaf: PathBuf,
    created: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryIntelRdtRecord {
    mountpoint: PathBuf,
    control_group: PathBuf,
    remove_control_group: bool,
    monitoring_group: Option<PathBuf>,
}

impl From<IntelRdtRecovery> for RecoveryIntelRdtRecord {
    fn from(recovery: IntelRdtRecovery) -> Self {
        Self {
            mountpoint: recovery.mountpoint,
            control_group: recovery.control_group,
            remove_control_group: recovery.remove_control_group,
            monitoring_group: recovery.monitoring_group,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    cgroup: Option<RecoveryCgroupRecord>,
    intel_rdt: Option<RecoveryIntelRdtRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviousContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    cgroup: Option<RecoveryCgroupRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    cgroup: Option<LegacyRecoveryCgroupRecord>,
}

/// Exact stopped-generation cleanup evidence retained after owner death.
#[derive(Debug, Clone)]
pub struct LinuxExecutorTombstone {
    target: ContainerTarget,
    config_digest: String,
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    record: ContainerRecoveryRecord,
}

impl LinuxExecutorTombstone {
    /// Exact container generation represented by this tombstone.
    #[must_use]
    pub fn target(&self) -> &ContainerTarget {
        &self.target
    }

    /// Immutable OCI configuration digest bound to the recovered generation.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }
}

pub(super) fn runtime_root_name(owner: ProcessIdentity) -> String {
    format!(
        "{RUNTIME_ROOT_PREFIX}{}-{:016x}",
        owner.pid, owner.start_time_ticks
    )
}

pub(super) fn transient_runtime_root_name(pid: u32) -> String {
    format!("{RUNTIME_ROOT_PREFIX}{pid}")
}

pub(super) async fn write_owner_record(runtime_root: &Path, owner: ProcessIdentity) -> Result<()> {
    let record = ExecutorOwnerRecord {
        schema_version: OWNER_SCHEMA_VERSION.to_string(),
        owner,
    };
    write_atomic_record(&runtime_root.join(OWNER_RECORD_NAME), &record)
}

pub(super) async fn write_container_record(
    runtime_directory: &Path,
    config_snapshot: &Path,
    target: &ContainerTarget,
    config_digest: &str,
    owner: ProcessIdentity,
    process: &PreparedProcess,
    cgroup_manager: Option<&CgroupManager>,
) -> Result<()> {
    let snapshot = read_bounded_plain_file(config_snapshot, MAX_RECORD_BYTES)?;
    let observed_digest = config_digest_for(&snapshot);
    if observed_digest != config_digest {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery snapshot digest mismatch for container {}: expected {config_digest}, observed {observed_digest}",
                target.id
            ),
        ));
    }
    let launcher = ProcessIdentity::capture(process.launcher_pid()?, "container launcher")?;
    let init = ProcessIdentity::capture(process.pid(), "container init")?;
    let cgroup = match (process.recovery_cgroup_paths(), cgroup_manager) {
        (None, _) => None,
        (Some(_), None) => {
            return Err(recovery_error(
                ErrorCode::Internal,
                "container recovery lost its private cgroup manager",
            ));
        }
        (Some((leaf, created)), Some(manager)) => Some(RecoveryCgroupRecord {
            authority_root: manager.authority_root().to_path_buf(),
            manager_root: manager.root().to_path_buf(),
            leaf: leaf.to_path_buf(),
            created: created.to_vec(),
        }),
    };
    if let Some(cgroup) = &cgroup {
        validate_cgroup_record(cgroup)?;
    }
    let intel_rdt = process
        .recovery_intel_rdt()
        .map(RecoveryIntelRdtRecord::from);
    if let Some(intel_rdt) = &intel_rdt {
        validate_intel_rdt_record(intel_rdt, target.id.as_str())?;
    }
    let record = ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: target.clone(),
        config_digest: config_digest.to_string(),
        owner,
        launcher,
        init,
        cgroup,
        intel_rdt,
    };
    write_atomic_record(&runtime_directory.join(CONTAINER_RECORD_NAME), &record)
}

pub(super) async fn recover_stale_generation(
    runtime_parent: &Path,
    current_runtime_root: &Path,
    target: &ContainerTarget,
    config_digest: &str,
    durable_pid: Option<i32>,
) -> Result<Option<LinuxExecutorTombstone>> {
    if target.generation.is_none() {
        return Err(recovery_error(
            ErrorCode::InvalidArgument,
            format!(
                "native Linux recovery requires an exact generation for container {}",
                target.id
            ),
        ));
    }
    let mut matches = Vec::new();
    let mut roots = list_real_directories(runtime_parent, RUNTIME_ROOT_PREFIX)?;
    roots.sort();
    for runtime_root in roots {
        if runtime_root == current_runtime_root {
            continue;
        }
        let Some(name) = runtime_root.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(name_identity) = parse_runtime_root_name(name) else {
            continue;
        };
        let owner: ExecutorOwnerRecord =
            read_json_record(&runtime_root.join(OWNER_RECORD_NAME), MAX_RECORD_BYTES)?;
        if owner.schema_version != OWNER_SCHEMA_VERSION || owner.owner != name_identity {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native executor owner record does not match protected root {}",
                    runtime_root.display()
                ),
            ));
        }
        let owner_live = owner.owner.is_live()?;
        let mut slots = list_real_directories(&runtime_root, "c-")?;
        slots.sort();
        for runtime_directory in slots {
            let record_path = runtime_directory.join(CONTAINER_RECORD_NAME);
            let record = match std::fs::symlink_metadata(&record_path) {
                Ok(_) => read_container_record(&record_path)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(recovery_io_error(
                        format!(
                            "failed to inspect native recovery record {}: {error}",
                            record_path.display()
                        ),
                        error,
                    ));
                }
            };
            validate_container_record(
                &record,
                &owner,
                &runtime_directory,
                target,
                config_digest,
                durable_pid,
            )?;
            if &record.target != target {
                continue;
            }
            if owner_live {
                return Err(recovery_error(
                    ErrorCode::Conflict,
                    format!(
                        "container {} generation {:?} still belongs to live native executor PID {}",
                        target.id, target.generation, owner.owner.pid
                    ),
                ));
            }
            matches.push(LinuxExecutorTombstone {
                target: target.clone(),
                config_digest: config_digest.to_string(),
                runtime_root: runtime_root.clone(),
                runtime_directory,
                record,
            });
        }
    }
    let tombstone = match matches.len() {
        1 => matches.pop().expect("one recovery match"),
        0 => return Ok(None),
        count => {
            return Err(recovery_error(
                ErrorCode::Conflict,
                format!(
                    "found {count} native recovery records for container {} generation {:?}",
                    target.id, target.generation
                ),
            ));
        }
    };

    let deadline = Instant::now() + TERMINATION_TIMEOUT;
    wait_for_identity_exit(tombstone.record.launcher, "container launcher", deadline).await?;
    wait_for_identity_exit(tombstone.record.init, "container init", deadline).await?;
    Ok(Some(tombstone))
}

pub(super) async fn delete_stale_generation(tombstone: &LinuxExecutorTombstone) -> Result<()> {
    let record = read_container_record(&tombstone.runtime_directory.join(CONTAINER_RECORD_NAME))?;
    if record != tombstone.record
        || record.target != tombstone.target
        || record.config_digest != tombstone.config_digest
    {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery evidence changed before delete for container {} generation {:?}",
                tombstone.target.id, tombstone.target.generation
            ),
        ));
    }
    if record.owner.is_live()? || record.launcher.is_live()? || record.init.is_live()? {
        return Err(recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to delete live native recovery resources for container {} generation {:?}",
                tombstone.target.id, tombstone.target.generation
            ),
        ));
    }
    if let Some(intel_rdt) = &record.intel_rdt {
        cleanup_intel_rdt(intel_rdt, record.target.id.as_str())?;
    }
    if let Some(cgroup) = &record.cgroup {
        cleanup_cgroup(cgroup)?;
    }
    ensure_private_directory(&tombstone.runtime_root, 0o700)?;
    ensure_private_directory(&tombstone.runtime_directory, 0o700)?;
    if tombstone.runtime_directory.parent() != Some(tombstone.runtime_root.as_path()) {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "refusing to delete native recovery directory outside its owner root: {}",
                tombstone.runtime_directory.display()
            ),
        ));
    }
    reject_symlinks_below(&tombstone.runtime_directory)?;
    if let Some(manifest) = load_device_target_manifest(&tombstone.runtime_directory)? {
        cleanup_device_target_manifest(&manifest)?;
    }
    std::fs::remove_dir_all(&tombstone.runtime_directory).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to remove recovered native container directory {}: {error}",
                tombstone.runtime_directory.display()
            ),
            error,
        )
    })?;
    cleanup_empty_runtime_root(&tombstone.runtime_root)
}

fn validate_container_record(
    record: &ContainerRecoveryRecord,
    owner: &ExecutorOwnerRecord,
    runtime_directory: &Path,
    target: &ContainerTarget,
    config_digest: &str,
    durable_pid: Option<i32>,
) -> Result<()> {
    if record.schema_version != CONTAINER_SCHEMA_VERSION || record.owner != owner.owner {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native container recovery record is not owned by {}",
                runtime_directory.display()
            ),
        ));
    }
    if let Some(cgroup) = &record.cgroup {
        validate_cgroup_record(cgroup)?;
    }
    if let Some(intel_rdt) = &record.intel_rdt {
        validate_intel_rdt_record(intel_rdt, record.target.id.as_str())?;
    }
    let snapshot = read_bounded_plain_file(
        &runtime_directory.join(CONFIG_SNAPSHOT_NAME),
        MAX_RECORD_BYTES,
    )?;
    let observed_digest = config_digest_for(&snapshot);
    if observed_digest != record.config_digest {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery configuration changed below {}: record {}, snapshot {observed_digest}",
                runtime_directory.display(), record.config_digest
            ),
        ));
    }
    if &record.target != target {
        return Ok(());
    }
    if record.config_digest != config_digest {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery config digest mismatch for container {} generation {:?}: durable {config_digest}, recovery {}",
                target.id, target.generation, record.config_digest
            ),
        ));
    }
    if durable_pid.is_some_and(|pid| pid != record.init.pid) {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery init PID mismatch for container {} generation {:?}: durable {durable_pid:?}, recovery {}",
                target.id, target.generation, record.init.pid
            ),
        ));
    }
    Ok(())
}

fn read_container_record(path: &Path) -> Result<ContainerRecoveryRecord> {
    let value: serde_json::Value = read_json_record(path, MAX_RECORD_BYTES)?;
    let schema_version = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native container recovery record {} has no schema version",
                    path.display()
                ),
            )
        })?;
    match schema_version {
        CONTAINER_SCHEMA_VERSION => serde_json::from_value(value).map_err(|error| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native container recovery record {} is invalid: {error}",
                    path.display()
                ),
            )
        }),
        CONTAINER_SCHEMA_VERSION_V2 => {
            let previous: PreviousContainerRecoveryRecord =
                serde_json::from_value(value).map_err(|error| {
                    recovery_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "v2 native container recovery record {} is invalid: {error}",
                            path.display()
                        ),
                    )
                })?;
            Ok(normalize_v2_container_record(previous))
        }
        CONTAINER_SCHEMA_VERSION_V1 => {
            let legacy: LegacyContainerRecoveryRecord =
                serde_json::from_value(value).map_err(|error| {
                    recovery_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "legacy native container recovery record {} is invalid: {error}",
                            path.display()
                        ),
                    )
                })?;
            normalize_legacy_container_record(legacy)
        }
        other => Err(recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "native container recovery record {} has unsupported schema {other}",
                path.display()
            ),
        )),
    }
}

fn normalize_legacy_container_record(
    legacy: LegacyContainerRecoveryRecord,
) -> Result<ContainerRecoveryRecord> {
    let cgroup = legacy
        .cgroup
        .map(|legacy| {
            let authority_root = legacy.manager_root.parent().ok_or_else(|| {
                recovery_error(
                    ErrorCode::PermissionDenied,
                    "legacy native recovery cgroup manager has no authority root",
                )
            })?;
            if authority_root != Path::new("/sys/fs/cgroup") {
                return Err(recovery_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "legacy native recovery cgroup is not a direct rootful cgroup-v2 manager: {}",
                        legacy.manager_root.display()
                    ),
                ));
            }
            let normalized = RecoveryCgroupRecord {
                authority_root: authority_root.to_path_buf(),
                manager_root: legacy.manager_root,
                leaf: legacy.leaf,
                created: legacy.created,
            };
            validate_cgroup_record(&normalized)?;
            Ok(normalized)
        })
        .transpose()?;
    Ok(ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: legacy.target,
        config_digest: legacy.config_digest,
        owner: legacy.owner,
        launcher: legacy.launcher,
        init: legacy.init,
        cgroup,
        intel_rdt: None,
    })
}

fn normalize_v2_container_record(
    previous: PreviousContainerRecoveryRecord,
) -> ContainerRecoveryRecord {
    ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: previous.target,
        config_digest: previous.config_digest,
        owner: previous.owner,
        launcher: previous.launcher,
        init: previous.init,
        cgroup: previous.cgroup,
        intel_rdt: None,
    }
}

fn validate_intel_rdt_record(intel_rdt: &RecoveryIntelRdtRecord, container_id: &str) -> Result<()> {
    validate_absolute_normalized(&intel_rdt.mountpoint, "resctrl mountpoint")?;
    validate_absolute_normalized(&intel_rdt.control_group, "resctrl control group")?;
    if intel_rdt.mountpoint == Path::new("/") {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery resctrl mountpoint must not be the filesystem root",
        ));
    }

    let root_control = intel_rdt.control_group == intel_rdt.mountpoint;
    let direct_child = intel_rdt.control_group.parent() == Some(intel_rdt.mountpoint.as_path())
        && intel_rdt.control_group.file_name().is_some();
    if !root_control && !direct_child {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery resctrl control group is outside the direct mount layout: {}",
                intel_rdt.control_group.display()
            ),
        ));
    }
    if intel_rdt.remove_control_group
        && (!direct_child
            || intel_rdt
                .control_group
                .file_name()
                .and_then(|name| name.to_str())
                != Some(container_id))
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery may remove only the container-owned resctrl CLOS for {container_id}: {}",
                intel_rdt.control_group.display()
            ),
        ));
    }
    if let Some(monitoring_group) = &intel_rdt.monitoring_group {
        validate_absolute_normalized(monitoring_group, "resctrl monitoring group")?;
        let expected = intel_rdt
            .control_group
            .join("mon_groups")
            .join(container_id);
        if monitoring_group != &expected {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native recovery resctrl monitoring group does not match the container-owned path: {}",
                    monitoring_group.display()
                ),
            ));
        }
    }
    if !intel_rdt.remove_control_group && intel_rdt.monitoring_group.is_none() {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery resctrl record does not own any cleanup path",
        ));
    }
    Ok(())
}

fn cleanup_intel_rdt(intel_rdt: &RecoveryIntelRdtRecord, container_id: &str) -> Result<()> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        recovery_io_error(
            format!("failed to read resctrl mount topology during native recovery: {error}"),
            error,
        )
    })?;
    cleanup_intel_rdt_with_mountinfo(intel_rdt, container_id, &mountinfo)
}

fn cleanup_intel_rdt_with_mountinfo(
    intel_rdt: &RecoveryIntelRdtRecord,
    container_id: &str,
    mountinfo: &str,
) -> Result<()> {
    validate_intel_rdt_record(intel_rdt, container_id)?;
    if !is_resctrl_mountpoint(mountinfo, &intel_rdt.mountpoint) {
        return Err(recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "native recovery resctrl mountpoint is no longer mounted as resctrl: {}",
                intel_rdt.mountpoint.display()
            ),
        )
        .retryable(true));
    }
    if let Some(monitoring_group) = &intel_rdt.monitoring_group {
        remove_recovered_resctrl_directory(monitoring_group, "monitoring group")?;
    }
    if intel_rdt.remove_control_group {
        remove_recovered_resctrl_directory(&intel_rdt.control_group, "control group")?;
    }
    Ok(())
}

fn remove_recovered_resctrl_directory(path: &Path, role: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "recovered resctrl {role} is not a real directory: {}",
                    path.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(recovery_io_error(
                format!(
                    "failed to inspect recovered resctrl {role} {}: {error}",
                    path.display()
                ),
                error,
            ));
        }
    }
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(recovery_io_error(
            format!(
                "failed to remove recovered resctrl {role} {}: {error}",
                path.display()
            ),
            error,
        )),
    }
}

async fn wait_for_identity_exit(
    identity: ProcessIdentity,
    role: &str,
    deadline: Instant,
) -> Result<()> {
    loop {
        if !identity.is_live()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(recovery_error(
                ErrorCode::DeadlineExceeded,
                format!(
                    "timed out waiting for exact {role} PID {} start-time {} to terminate after native owner death",
                    identity.pid, identity.start_time_ticks
                ),
            )
            .retryable(true));
        }
        sleep(TERMINATION_POLL_INTERVAL).await;
    }
}

fn validate_cgroup_record(cgroup: &RecoveryCgroupRecord) -> Result<()> {
    validate_absolute_normalized(&cgroup.authority_root, "cgroup authority root")?;
    validate_absolute_normalized(&cgroup.manager_root, "cgroup manager root")?;
    if cgroup.authority_root == Path::new("/") {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery cgroup authority root must not be the filesystem root",
        ));
    }
    let manager_name = cgroup
        .manager_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !manager_name.starts_with("a3s-oci-")
        || cgroup.manager_root.parent() != Some(cgroup.authority_root.as_path())
        || cgroup.created.is_empty()
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery cgroup manager is outside the runtime-owned layout: {}",
                cgroup.manager_root.display()
            ),
        ));
    }
    validate_absolute_normalized(&cgroup.leaf, "cgroup leaf")?;
    if cgroup.leaf == cgroup.manager_root || !cgroup.leaf.starts_with(&cgroup.manager_root) {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery cgroup leaf escapes manager root: {}",
                cgroup.leaf.display()
            ),
        ));
    }
    for path in &cgroup.created {
        validate_absolute_normalized(path, "created cgroup")?;
        if path == &cgroup.manager_root || !path.starts_with(&cgroup.manager_root) {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native recovery cgroup path escapes manager root: {}",
                    path.display()
                ),
            ));
        }
    }
    if !cgroup.created.iter().any(|path| path == &cgroup.leaf)
        && !cgroup
            .created
            .iter()
            .any(|path| cgroup.leaf.starts_with(path))
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery cgroup leaf is not below a created path",
        ));
    }
    Ok(())
}

fn cleanup_cgroup(cgroup: &RecoveryCgroupRecord) -> Result<()> {
    validate_cgroup_record(cgroup)?;
    let freeze = cgroup.leaf.join("cgroup.freeze");
    match std::fs::write(&freeze, b"0") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(recovery_io_error(
                format!(
                    "failed to thaw recovered native cgroup {}: {error}",
                    cgroup.leaf.display()
                ),
                error,
            ));
        }
    }
    for path in cgroup.created.iter().rev() {
        match std::fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error)
                if error.kind() == io::ErrorKind::DirectoryNotEmpty && path != &cgroup.leaf =>
            {
                // OCI cgroupsPath may contain a shared intermediate prefix.
                // Removing the exact leaf is mandatory; a still-populated
                // ancestor remains owned by another durable generation.
            }
            Err(error) => {
                return Err(recovery_io_error(
                    format!(
                        "failed to remove recovered native cgroup {}: {error}",
                        path.display()
                    ),
                    error,
                ));
            }
        }
    }
    match std::fs::remove_dir(&cgroup.manager_root) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(recovery_io_error(
            format!(
                "failed to remove empty native cgroup manager {}: {error}",
                cgroup.manager_root.display()
            ),
            error,
        )),
    }
}

fn cleanup_empty_runtime_root(runtime_root: &Path) -> Result<()> {
    let mut remaining_slots = false;
    for entry in std::fs::read_dir(runtime_root).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect recovered executor root {}: {error}",
                runtime_root.display()
            ),
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            recovery_io_error("failed to enumerate recovered executor root", error)
        })?;
        let name = entry.file_name();
        if name == OWNER_RECORD_NAME {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to inspect recovered entry {}",
                    entry.path().display()
                ),
                error,
            )
        })?;
        if file_type.is_dir()
            && !file_type.is_symlink()
            && name.to_str().is_some_and(|name| name.starts_with("c-"))
        {
            remaining_slots = true;
            continue;
        }
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "unexpected entry remains in recovered executor root: {}",
                entry.path().display()
            ),
        ));
    }
    if remaining_slots {
        return Ok(());
    }
    std::fs::remove_file(runtime_root.join(OWNER_RECORD_NAME)).map_err(|error| {
        recovery_io_error("failed to remove recovered executor owner record", error)
    })?;
    std::fs::remove_dir(runtime_root).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to remove empty recovered executor root {}: {error}",
                runtime_root.display()
            ),
            error,
        )
    })
}

fn list_real_directories(parent: &Path, prefix: &str) -> Result<Vec<PathBuf>> {
    ensure_private_directory(parent, 0o700)?;
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(parent).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to enumerate native recovery root {}: {error}",
                parent.display()
            ),
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            recovery_io_error("failed to enumerate native recovery entry", error)
        })?;
        let name = entry.file_name();
        if !name.to_str().is_some_and(|name| name.starts_with(prefix)) {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to inspect native recovery entry {}",
                    entry.path().display()
                ),
                error,
            )
        })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native recovery entry must be a real directory: {}",
                    entry.path().display()
                ),
            ));
        }
        ensure_private_directory(&entry.path(), 0o700)?;
        paths.push(entry.path());
    }
    Ok(paths)
}

fn ensure_private_directory(path: &Path, mode: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect protected directory {}: {error}",
                path.display()
            ),
            error,
        )
    })?;
    // SAFETY: geteuid has no preconditions or failure result.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != mode
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "protected directory {} must be owned by UID {uid} with mode {mode:04o}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn reject_symlinks_below(path: &Path) -> Result<()> {
    for entry in std::fs::read_dir(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect recovery directory {}: {error}",
                path.display()
            ),
            error,
        )
    })? {
        let entry =
            entry.map_err(|error| recovery_io_error("failed to inspect recovery entry", error))?;
        let file_type = entry.file_type().map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to inspect recovery entry {}",
                    entry.path().display()
                ),
                error,
            )
        })?;
        if file_type.is_symlink() {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "recovery directory contains a symlink: {}",
                    entry.path().display()
                ),
            ));
        }
        if file_type.is_dir() {
            reject_symlinks_below(&entry.path())?;
        }
    }
    Ok(())
}

fn parse_runtime_root_name(name: &str) -> Option<ProcessIdentity> {
    let suffix = name.strip_prefix(RUNTIME_ROOT_PREFIX)?;
    let (pid, start) = suffix.split_once('-')?;
    if start.contains('-') {
        return None;
    }
    let identity = ProcessIdentity {
        pid: pid.parse().ok()?,
        start_time_ticks: u64::from_str_radix(start, 16).ok()?,
    };
    (identity.pid > 0 && runtime_root_name(identity) == name).then_some(identity)
}

fn process_observation(pid: i32) -> Result<Option<ProcessObservation>> {
    if pid <= 0 {
        return Err(recovery_error(
            ErrorCode::InvalidArgument,
            format!("recovery process PID must be positive; received {pid}"),
        ));
    }
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(recovery_io_error(
                format!(
                    "failed to read process identity {}: {error}",
                    path.display()
                ),
                error,
            ));
        }
    };
    if contents.len() > 4096 {
        return Err(recovery_error(
            ErrorCode::ResourceExhausted,
            format!("process identity exceeds 4096 bytes: {}", path.display()),
        ));
    }
    let closing = contents.rfind(") ").ok_or_else(|| {
        recovery_error(
            ErrorCode::FailedPrecondition,
            format!("process identity is malformed: {}", path.display()),
        )
    })?;
    let reported_pid = contents[..]
        .split_once(" (")
        .and_then(|(pid, _)| pid.parse::<i32>().ok())
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!("process identity has no valid PID: {}", path.display()),
            )
        })?;
    if reported_pid != pid {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "process identity PID mismatch at {}: expected {pid}, observed {reported_pid}",
                path.display()
            ),
        ));
    }
    let fields = contents[closing + 2..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let state = fields
        .first()
        .filter(|field| field.len() == 1)
        .and_then(|field| field.as_bytes().first())
        .copied()
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!("process identity has no valid state: {}", path.display()),
            )
        })?;
    let start_time_ticks = fields
        .get(19)
        .and_then(|field| field.parse::<u64>().ok())
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "process identity has no valid start time: {}",
                    path.display()
                ),
            )
        })?;
    Ok(Some(ProcessObservation {
        start_time_ticks,
        state,
    }))
}

fn write_atomic_record<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(|error| {
        recovery_error(
            ErrorCode::Internal,
            format!("failed to encode native recovery record: {error}"),
        )
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_RECORD_BYTES {
        return Err(recovery_error(
            ErrorCode::ResourceExhausted,
            "native recovery record exceeds its bounded size",
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::InvalidArgument,
                format!(
                    "native recovery record has no UTF-8 filename: {}",
                    path.display()
                ),
            )
        })?;
    let pending = path.with_file_name(format!(".{name}.next"));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let result = (|| -> io::Result<()> {
        let mut file = options.open(&pending)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        std::fs::hard_link(&pending, path)?;
        std::fs::remove_file(&pending)?;
        File::open(path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "recovery record has no parent")
        })?)?
        .sync_all()
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&pending);
        return Err(recovery_io_error(
            format!(
                "failed to persist native recovery record {}: {error}",
                path.display()
            ),
            error,
        ));
    }
    Ok(())
}

pub(super) fn read_json_record<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T> {
    let bytes = read_bounded_plain_file(path, limit)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "native recovery record {} is invalid: {error}",
                path.display()
            ),
        )
    })
}

fn read_bounded_plain_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect native recovery file {}: {error}",
                path.display()
            ),
            error,
        )
    })?;
    // SAFETY: geteuid has no preconditions or failure result.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > limit
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery file {} must be a bounded plain mode-0600 file owned by UID {uid}",
                path.display()
            ),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to open native recovery file {}: {error}",
                path.display()
            ),
            error,
        )
    })?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to read native recovery file {}: {error}",
                    path.display()
                ),
                error,
            )
        })?;
    if bytes.len() as u64 > limit {
        return Err(recovery_error(
            ErrorCode::ResourceExhausted,
            format!(
                "native recovery file grew beyond its limit: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

fn config_digest_for(contents: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(contents))
}

fn validate_absolute_normalized(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "{label} must be absolute and normalized: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn recovery_io_error(message: impl Into<String>, error: io::Error) -> Error {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::FailedPrecondition,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        _ => ErrorCode::Internal,
    };
    recovery_error(code, message)
}

fn recovery_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("native-linux-recover")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn runtime_root_name_round_trips_exact_process_identity() {
        let identity = ProcessIdentity {
            pid: 42_001,
            start_time_ticks: 0x1234_abcd,
        };
        let name = runtime_root_name(identity);
        assert_eq!(parse_runtime_root_name(&name), Some(identity));
        assert_eq!(parse_runtime_root_name("a3s-oci-agent-42001"), None);
        assert_eq!(
            parse_runtime_root_name("a3s-oci-agent-0-0000000000000001"),
            None
        );
    }

    #[test]
    fn current_process_identity_is_live_and_pid_bound() {
        let identity = ProcessIdentity::current().expect("current process identity");
        assert!(identity.is_live().expect("inspect current identity"));
        assert_eq!(identity.pid as u32, std::process::id());

        let stale = ProcessIdentity {
            pid: identity.pid,
            start_time_ticks: identity.start_time_ticks.saturating_add(1),
        };
        assert!(
            !stale.is_live().expect("inspect reused numeric PID"),
            "a reused numeric PID must not match the authenticated start time"
        );
    }

    #[test]
    fn zombie_and_dead_process_states_are_terminal() {
        for state in *b"ZXx" {
            assert!(ProcessObservation {
                start_time_ticks: 1,
                state,
            }
            .is_terminated());
        }
        for state in *b"RSDTtI" {
            assert!(!ProcessObservation {
                start_time_ticks: 1,
                state,
            }
            .is_terminated());
        }
    }

    #[test]
    fn cgroup_record_rejects_broad_or_escaping_paths() {
        let broad = RecoveryCgroupRecord {
            authority_root: PathBuf::from("/sys/fs/cgroup"),
            manager_root: PathBuf::from("/sys/fs/cgroup"),
            leaf: PathBuf::from("/sys/fs/cgroup/workload"),
            created: vec![PathBuf::from("/sys/fs/cgroup/workload")],
        };
        assert!(validate_cgroup_record(&broad).is_err());

        let escaping = RecoveryCgroupRecord {
            authority_root: PathBuf::from("/sys/fs/cgroup"),
            manager_root: PathBuf::from("/sys/fs/cgroup/a3s-oci-1-test"),
            leaf: PathBuf::from("/sys/fs/cgroup/unrelated"),
            created: vec![PathBuf::from("/sys/fs/cgroup/unrelated")],
        };
        assert!(validate_cgroup_record(&escaping).is_err());

        let unrelated_authority = RecoveryCgroupRecord {
            authority_root: PathBuf::from("/sys/fs/cgroup/delegated-a"),
            manager_root: PathBuf::from("/sys/fs/cgroup/delegated-b/a3s-oci-1-test"),
            leaf: PathBuf::from("/sys/fs/cgroup/delegated-b/a3s-oci-1-test/workload"),
            created: vec![PathBuf::from(
                "/sys/fs/cgroup/delegated-b/a3s-oci-1-test/workload",
            )],
        };
        assert!(validate_cgroup_record(&unrelated_authority).is_err());
    }

    #[test]
    fn legacy_rootful_recovery_cgroup_normalizes_to_the_v3_model() {
        let legacy = LegacyContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V1.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("legacy-rootful").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            cgroup: Some(LegacyRecoveryCgroupRecord {
                manager_root: PathBuf::from("/sys/fs/cgroup/a3s-oci-100-test"),
                leaf: PathBuf::from("/sys/fs/cgroup/a3s-oci-100-test/workload"),
                created: vec![PathBuf::from("/sys/fs/cgroup/a3s-oci-100-test/workload")],
            }),
        };

        let normalized =
            normalize_legacy_container_record(legacy).expect("normalize rootful v1 record");
        assert_eq!(normalized.schema_version, CONTAINER_SCHEMA_VERSION);
        assert_eq!(
            normalized.cgroup.expect("normalized cgroup").authority_root,
            PathBuf::from("/sys/fs/cgroup")
        );
    }

    #[test]
    fn v2_recovery_record_normalizes_without_inventing_resctrl_ownership() {
        let previous = PreviousContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V2.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("v2-record").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            cgroup: None,
        };

        let normalized = normalize_v2_container_record(previous);
        assert_eq!(normalized.schema_version, CONTAINER_SCHEMA_VERSION);
        assert!(normalized.intel_rdt.is_none());
    }

    #[test]
    fn intel_rdt_recovery_rejects_broad_or_tampered_paths() {
        let valid = RecoveryIntelRdtRecord {
            mountpoint: PathBuf::from("/sys/fs/resctrl"),
            control_group: PathBuf::from("/sys/fs/resctrl/container-rdt"),
            remove_control_group: true,
            monitoring_group: Some(PathBuf::from(
                "/sys/fs/resctrl/container-rdt/mon_groups/container-rdt",
            )),
        };
        validate_intel_rdt_record(&valid, "container-rdt").expect("valid resctrl ownership");
        let error = cleanup_intel_rdt_with_mountinfo(
            &valid,
            "container-rdt",
            "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
        )
        .expect_err("recovery must not remove paths outside a current resctrl mount");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);

        let mut tampered = valid.clone();
        tampered.mountpoint = PathBuf::from("/");
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());

        let mut tampered = valid.clone();
        tampered.control_group = PathBuf::from("/sys/fs/resctrl/shared/container-rdt");
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());

        let mut tampered = valid.clone();
        tampered.control_group = PathBuf::from("/sys/fs/resctrl/unrelated");
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());

        let mut tampered = valid;
        tampered.monitoring_group = Some(PathBuf::from(
            "/sys/fs/resctrl/container-rdt/mon_groups/another-container",
        ));
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());
    }

    #[test]
    fn intel_rdt_recovery_removes_monitoring_before_owned_control_and_retries() {
        let temporary = tempfile::tempdir().expect("temporary resctrl fixture");
        let mountpoint = temporary.path().join("resctrl");
        let control_group = mountpoint.join("container-rdt");
        let monitoring_parent = control_group.join("mon_groups");
        let monitoring_group = monitoring_parent.join("container-rdt");
        std::fs::create_dir_all(&monitoring_group).expect("monitoring group");
        let record = RecoveryIntelRdtRecord {
            mountpoint,
            control_group: control_group.clone(),
            remove_control_group: true,
            monitoring_group: Some(monitoring_group.clone()),
        };
        let mountinfo = format!(
            "30 23 0:27 / {} rw - resctrl resctrl rw\n",
            record.mountpoint.display()
        );

        let error = cleanup_intel_rdt_with_mountinfo(&record, "container-rdt", &mountinfo)
            .expect_err("ordinary fixture still contains the virtual mon_groups parent");
        assert_eq!(error.code, ErrorCode::Internal);
        assert!(!monitoring_group.exists());
        assert!(control_group.exists());

        std::fs::remove_dir(&monitoring_parent).expect("remove fixture monitoring parent");
        cleanup_intel_rdt_with_mountinfo(&record, "container-rdt", &mountinfo)
            .expect("retry resctrl cleanup");
        assert!(!control_group.exists());
    }

    #[test]
    fn legacy_delegated_recovery_cgroup_fails_closed() {
        let legacy = LegacyContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V1.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("legacy-delegated").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            cgroup: Some(LegacyRecoveryCgroupRecord {
                manager_root: PathBuf::from("/sys/fs/cgroup/delegated/a3s-oci-100-test"),
                leaf: PathBuf::from("/sys/fs/cgroup/delegated/a3s-oci-100-test/workload"),
                created: vec![PathBuf::from(
                    "/sys/fs/cgroup/delegated/a3s-oci-100-test/workload",
                )],
            }),
        };

        let error = normalize_legacy_container_record(legacy)
            .expect_err("v1 delegated authority is unknowable");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("not a direct rootful"));
    }

    #[tokio::test]
    async fn stale_record_recovers_only_with_exact_snapshot_and_cleans_its_root() {
        let fixture = RecoveryFixture::new("exact-record");
        let tombstone = recover_stale_generation(
            &fixture.parent,
            &fixture.current_root,
            &fixture.target,
            &fixture.digest,
            Some(fixture.init.pid),
        )
        .await
        .expect("search exact stale generation")
        .expect("recover exact stale generation");
        assert_eq!(tombstone.target(), &fixture.target);
        delete_stale_generation(&tombstone)
            .await
            .expect("delete exact stale generation");
        assert!(!fixture.stale_root.exists());
    }

    #[tokio::test]
    async fn changed_snapshot_fails_closed_before_stopped_recovery() {
        let fixture = RecoveryFixture::new("changed-snapshot");
        std::fs::write(fixture.slot.join(CONFIG_SNAPSHOT_NAME), b"changed")
            .expect("change protected snapshot fixture");
        let error = recover_stale_generation(
            &fixture.parent,
            &fixture.current_root,
            &fixture.target,
            &fixture.digest,
            Some(fixture.init.pid),
        )
        .await
        .expect_err("changed snapshot must fail closed");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(fixture.stale_root.exists());
    }

    struct RecoveryFixture {
        _temporary: tempfile::TempDir,
        parent: PathBuf,
        current_root: PathBuf,
        stale_root: PathBuf,
        slot: PathBuf,
        target: ContainerTarget,
        digest: String,
        init: ProcessIdentity,
    }

    impl RecoveryFixture {
        fn new(id: &str) -> Self {
            let temporary = tempfile::tempdir().expect("temporary recovery parent");
            let parent = temporary.path().join("executor");
            std::fs::create_dir(&parent).expect("executor parent");
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
                .expect("protect executor parent");
            let current_root = parent.join("current");
            std::fs::create_dir(&current_root).expect("current root");
            std::fs::set_permissions(&current_root, std::fs::Permissions::from_mode(0o700))
                .expect("protect current root");

            let owner = ProcessIdentity {
                pid: 2_000_000,
                start_time_ticks: 0xabc,
            };
            let stale_root = parent.join(runtime_root_name(owner));
            std::fs::create_dir(&stale_root).expect("stale root");
            std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700))
                .expect("protect stale root");
            write_atomic_record(
                &stale_root.join(OWNER_RECORD_NAME),
                &ExecutorOwnerRecord {
                    schema_version: OWNER_SCHEMA_VERSION.to_string(),
                    owner,
                },
            )
            .expect("owner record");

            let slot = stale_root.join("c-0000000000000001");
            std::fs::create_dir(&slot).expect("container slot");
            std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o700))
                .expect("protect container slot");
            let config = br#"{"ociVersion":"1.3.0"}"#;
            let digest = config_digest_for(config);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
                .open(slot.join(CONFIG_SNAPSHOT_NAME))
                .and_then(|mut file| file.write_all(config))
                .expect("configuration snapshot");
            let target = ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new(id).expect("container ID"),
                a3s_oci_sdk::Generation(1),
            );
            let init = ProcessIdentity {
                pid: 2_000_002,
                start_time_ticks: 0xdef,
            };
            write_atomic_record(
                &slot.join(CONTAINER_RECORD_NAME),
                &ContainerRecoveryRecord {
                    schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                    target: target.clone(),
                    config_digest: digest.clone(),
                    owner,
                    launcher: ProcessIdentity {
                        pid: 2_000_001,
                        start_time_ticks: 0xcde,
                    },
                    init,
                    cgroup: None,
                    intel_rdt: None,
                },
            )
            .expect("container recovery record");

            Self {
                _temporary: temporary,
                parent,
                current_root,
                stale_root,
                slot,
                target,
                digest,
                init,
            }
        }
    }
}
