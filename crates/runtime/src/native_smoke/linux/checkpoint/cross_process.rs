use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    canonical_json_bytes, CheckpointArtifactPath, CheckpointReference, ContainerId,
    ContainerOperationRequest, ContainerTarget, CreateAttachments, DeleteMode, DeleteRequest,
    Error, ErrorCode, ExitStatus, Generation, IsolationRequest, KillRequest, ListRequest,
    OciBundle, OperationContext, OperationId, RestoreRequest, Result, RuntimeClient, Signal,
    StateRequest, WaitRequest,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::timeout;

use crate::fault::{
    DriverBoundaryStage, DriverOperation, DurableMutation, FaultInjector, FaultPoint,
    FileCommitStage,
};
use crate::{
    HostRuntimeService, NativeLinuxCheckpointRestoreCrashPoint, NativeLinuxCheckpointSmokeReport,
    NativeLinuxDriver, RuntimeDriver,
};

use super::{
    artifact_identity, best_effort_delete, call, directory_is_empty, no_pending_entries, operation,
    CHECKPOINT_STATE_DIRECTORY, CHECKPOINT_TIMEOUT,
};

const OWNER_EXIT_CODE: i32 = 86;
const OWNER_EVIDENCE_SCHEMA_V1: &str = "a3s.oci.native-restore-owner-exit.v1";
const MAX_REQUEST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;

#[derive(Clone)]
pub(super) struct CrossProcessRestoreSeed {
    id: ContainerId,
    bundle: OciBundle,
    artifact_path: CheckpointArtifactPath,
    isolation: IsolationRequest,
    attachments: CreateAttachments,
    reference: CheckpointReference,
}

impl CrossProcessRestoreSeed {
    pub(super) fn new(
        id: ContainerId,
        bundle: OciBundle,
        artifact_path: CheckpointArtifactPath,
        isolation: IsolationRequest,
        attachments: CreateAttachments,
        reference: CheckpointReference,
    ) -> Self {
        Self {
            id,
            bundle,
            artifact_path,
            isolation,
            attachments,
            reference,
        }
    }

    pub(super) fn request(&self, context: OperationContext) -> Result<RestoreRequest> {
        RestoreRequest::new(
            context,
            self.id.clone(),
            self.bundle.clone(),
            self.artifact_path.clone(),
            self.isolation.clone(),
            self.attachments.clone(),
            self.reference.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreOwnerExitEvidence {
    schema_version: String,
    crash_point: NativeLinuxCheckpointRestoreCrashPoint,
    owner_pid: u32,
    operation_id: OperationId,
}

impl RestoreOwnerExitEvidence {
    fn new(crash_point: NativeLinuxCheckpointRestoreCrashPoint, operation_id: OperationId) -> Self {
        Self {
            schema_version: OWNER_EVIDENCE_SCHEMA_V1.to_string(),
            crash_point,
            owner_pid: std::process::id(),
            operation_id,
        }
    }
}

#[derive(Debug)]
struct RestoreOwnerFault {
    crash_point: NativeLinuxCheckpointRestoreCrashPoint,
    ready_file: PathBuf,
    evidence: RestoreOwnerExitEvidence,
    armed: AtomicBool,
    fired: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreOwnerAction {
    Continue,
    FailAfterDriverCall,
    ExitAfterHostCommit,
}

impl RestoreOwnerFault {
    fn new(
        crash_point: NativeLinuxCheckpointRestoreCrashPoint,
        ready_file: PathBuf,
        operation_id: OperationId,
    ) -> Self {
        Self {
            crash_point,
            ready_file,
            evidence: RestoreOwnerExitEvidence::new(crash_point, operation_id),
            armed: AtomicBool::new(false),
            fired: AtomicBool::new(false),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }

    fn publish_ready(&self) -> Result<()> {
        write_private_json(&self.ready_file, &self.evidence).map_err(|message| {
            Error::new(ErrorCode::Unavailable, message)
                .for_operation("native-linux-checkpoint-restore-owner")
        })
    }

    fn take_action(&self, point: FaultPoint) -> RestoreOwnerAction {
        if !self.armed.load(Ordering::SeqCst) {
            return RestoreOwnerAction::Continue;
        }
        match self.crash_point {
            NativeLinuxCheckpointRestoreCrashPoint::AfterDriverCall
                if matches!(
                    point,
                    FaultPoint::DriverBoundary {
                        operation: DriverOperation::Restore,
                        stage: DriverBoundaryStage::AfterCall,
                    }
                ) && !self.fired.swap(true, Ordering::SeqCst) =>
            {
                RestoreOwnerAction::FailAfterDriverCall
            }
            NativeLinuxCheckpointRestoreCrashPoint::AfterHostCommit
                if matches!(
                    point,
                    FaultPoint::DurableFile {
                        mutation: DurableMutation::CompleteRestoreOperation,
                        stage: FileCommitStage::ParentDirectorySynced,
                    }
                ) && !self.fired.swap(true, Ordering::SeqCst) =>
            {
                RestoreOwnerAction::ExitAfterHostCommit
            }
            _ => RestoreOwnerAction::Continue,
        }
    }
}

impl FaultInjector for RestoreOwnerFault {
    fn check(&self, point: FaultPoint) -> Result<()> {
        match self.take_action(point) {
            RestoreOwnerAction::Continue => Ok(()),
            RestoreOwnerAction::FailAfterDriverCall => Err(Error::new(
                ErrorCode::Unavailable,
                "injected owner exit after native restore driver return",
            )
            .for_operation("native-linux-checkpoint-restore-owner")
            .retryable(true)),
            RestoreOwnerAction::ExitAfterHostCommit => {
                self.publish_ready()?;
                std::process::exit(OWNER_EXIT_CODE);
            }
        }
    }
}

#[derive(Debug)]
struct CaseEvidence {
    owner_replaced: bool,
    service_reopened: bool,
    replay_exact: bool,
    restored_pid_live: bool,
    artifact_unchanged: bool,
    cleanup_exact: bool,
    generation: Generation,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn qualify(
    init_executable: &Path,
    criu_executable: &Path,
    session_root: &Path,
    executor_parent: &Path,
    state_root: &Path,
    nonce: &str,
    seed: &CrossProcessRestoreSeed,
    previous_generation: Generation,
    expected_artifact: &(String, u64),
    report: &mut NativeLinuxCheckpointSmokeReport,
) -> std::result::Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| {
        format!("failed to resolve checkpoint qualification executable: {error}")
    })?;
    let after_call = run_case(
        &executable,
        init_executable,
        criu_executable,
        session_root,
        executor_parent,
        state_root,
        nonce,
        seed,
        NativeLinuxCheckpointRestoreCrashPoint::AfterDriverCall,
        previous_generation,
        expected_artifact,
    )
    .await?;
    report.restore_after_call_owner_replaced = after_call.owner_replaced;
    report.restore_after_call_service_reopened = after_call.service_reopened;
    report.restore_after_call_replay_exact = after_call.replay_exact;

    let after_commit = run_case(
        &executable,
        init_executable,
        criu_executable,
        session_root,
        executor_parent,
        state_root,
        nonce,
        seed,
        NativeLinuxCheckpointRestoreCrashPoint::AfterHostCommit,
        after_call.generation,
        expected_artifact,
    )
    .await?;
    report.restore_after_commit_owner_replaced = after_commit.owner_replaced;
    report.restore_after_commit_service_reopened = after_commit.service_reopened;
    report.restore_after_commit_replay_exact = after_commit.replay_exact;
    report.cross_process_restored_pids_live =
        after_call.restored_pid_live && after_commit.restored_pid_live;
    report.cross_process_artifact_unchanged =
        after_call.artifact_unchanged && after_commit.artifact_unchanged;
    report.cross_process_restore_cleanup_exact =
        after_call.cleanup_exact && after_commit.cleanup_exact;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_case(
    executable: &Path,
    init_executable: &Path,
    criu_executable: &Path,
    session_root: &Path,
    executor_parent: &Path,
    state_root: &Path,
    nonce: &str,
    seed: &CrossProcessRestoreSeed,
    crash_point: NativeLinuxCheckpointRestoreCrashPoint,
    previous_generation: Generation,
    expected_artifact: &(String, u64),
) -> std::result::Result<CaseEvidence, String> {
    let label = match crash_point {
        NativeLinuxCheckpointRestoreCrashPoint::AfterDriverCall => "after-call",
        NativeLinuxCheckpointRestoreCrashPoint::AfterHostCommit => "after-commit",
    };
    let context = operation(nonce, &format!("restore-owner-{label}"))?;
    let request = seed
        .request(context)
        .map_err(|error| format!("failed to construct {label} restore request: {error}"))?;
    let request_file = session_root.join(format!("restore-owner-{label}.json"));
    let ready_file = session_root.join(format!("restore-owner-{label}.ready.json"));
    write_private_json_async(&request_file, &request).await?;

    let mut child = Command::new(executable);
    child
        .arg("native-linux-checkpoint-restore-owner")
        .arg("--agent")
        .arg(init_executable)
        .arg("--criu")
        .arg(criu_executable)
        .arg("--state-root")
        .arg(state_root)
        .arg("--executor-parent")
        .arg(executor_parent)
        .arg("--request-file")
        .arg(&request_file)
        .arg("--ready-file")
        .arg(&ready_file)
        .arg("--crash-point")
        .arg(label)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = child
        .spawn()
        .map_err(|error| format!("failed to spawn {label} restore owner: {error}"))?;
    let child_pid = child
        .id()
        .ok_or_else(|| format!("{label} restore owner has no live process ID"))?;
    let status = match timeout(CHECKPOINT_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            return Err(format!("failed to wait for {label} restore owner: {error}"));
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(format!(
                "{label} restore owner did not exit before its deadline"
            ));
        }
    };
    let evidence: RestoreOwnerExitEvidence =
        read_private_json_async(&ready_file, MAX_EVIDENCE_BYTES).await?;
    let owner_replaced = status.code() == Some(OWNER_EXIT_CODE)
        && evidence.schema_version == OWNER_EVIDENCE_SCHEMA_V1
        && evidence.crash_point == crash_point
        && evidence.owner_pid == child_pid
        && evidence.owner_pid != std::process::id()
        && evidence.operation_id == request.context().operation_id;
    if !owner_replaced {
        return Err(format!(
            "{label} restore owner did not retain exact exit evidence: status={status}, evidence={evidence:?}"
        ));
    }

    let driver = Arc::new(
        NativeLinuxDriver::open_experimental_with_criu(
            executor_parent,
            init_executable,
            criu_executable,
        )
        .await
        .map_err(|error| format!("failed to reopen {label} CRIU driver: {error}"))?,
    );
    let executor_root = driver.executor_root().to_path_buf();
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let service = HostRuntimeService::open(state_root, runtime_driver)
        .await
        .map_err(|error| format!("failed to reopen {label} Host service: {error}"))?;
    let client = RuntimeClient::new(service.clone());
    let mut cleanup_target = None;
    let exercise = async {
        let restored = call(
            &format!("recover {label} restore on replacement owner"),
            CHECKPOINT_TIMEOUT,
            client.restore(request.clone()),
        )
        .await?;
        if restored.restored().generation <= previous_generation
            || *restored.restored().state.status() != ContainerState::Running
            || !restored.restored().is_paused()
        {
            return Err(format!(
                "{label} replacement did not return a newer paused running generation"
            ));
        }
        let target = ContainerTarget::exact(request.id().clone(), restored.restored().generation);
        cleanup_target = Some(target.clone());
        let state = call(
            &format!("observe {label} replacement state"),
            CHECKPOINT_TIMEOUT,
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        let replay = call(
            &format!("replay {label} replacement restore"),
            CHECKPOINT_TIMEOUT,
            client.restore(request.clone()),
        )
        .await?;
        let replay_exact = replay == restored && state == *restored.restored();
        let restored_pid = restored
            .restored()
            .state
            .pid()
            .ok_or_else(|| format!("{label} replacement restore returned no init PID"))?;
        let restored_pid_live = process_is_live(restored_pid);
        if !replay_exact || !restored_pid_live {
            return Err(format!(
                "{label} replacement did not retain exact replay and a live restored PID"
            ));
        }

        call(
            &format!("resume {label} restored generation"),
            CHECKPOINT_TIMEOUT,
            client.resume(ContainerOperationRequest {
                context: operation(nonce, &format!("restore-owner-{label}-resume"))?,
                target: target.clone(),
            }),
        )
        .await?;
        call(
            &format!("kill {label} restored generation"),
            CHECKPOINT_TIMEOUT,
            client.kill(KillRequest {
                context: operation(nonce, &format!("restore-owner-{label}-kill"))?,
                target: target.clone(),
                signal: Signal::new(libc::SIGKILL)
                    .map_err(|error| format!("failed to construct {label} SIGKILL: {error}"))?,
                all: true,
            }),
        )
        .await?;
        let exit = call(
            &format!("wait {label} restored generation"),
            CHECKPOINT_TIMEOUT,
            client.wait(WaitRequest {
                target: target.clone(),
                timeout_ms: Some(10_000),
            }),
        )
        .await?;
        let expected_exit = ExitStatus::signaled(libc::SIGKILL, false)
            .map_err(|error| format!("failed to construct {label} exit status: {error}"))?;
        if exit != expected_exit {
            return Err(format!(
                "{label} replacement returned unexpected exit status"
            ));
        }
        call(
            &format!("delete {label} restored generation"),
            CHECKPOINT_TIMEOUT,
            client.delete(DeleteRequest {
                context: operation(nonce, &format!("restore-owner-{label}-delete"))?,
                target,
                mode: DeleteMode::Force,
            }),
        )
        .await?;
        cleanup_target = None;

        let artifact_unchanged =
            artifact_identity(seed.artifact_path.as_path()).await? == *expected_artifact;
        let operations = executor_parent
            .join(CHECKPOINT_STATE_DIRECTORY)
            .join("restore-operations");
        let staging = executor_parent
            .join(CHECKPOINT_STATE_DIRECTORY)
            .join("restore-staging");
        let cleanup_exact = directory_is_empty(&operations).await?
            && directory_is_empty(&staging).await?
            && no_pending_entries(session_root).await?;
        Ok(CaseEvidence {
            owner_replaced,
            service_reopened: true,
            replay_exact,
            restored_pid_live,
            artifact_unchanged,
            cleanup_exact,
            generation: restored.restored().generation,
        })
    }
    .await;

    if exercise.is_err() {
        if let Some(target) = cleanup_target.as_ref() {
            best_effort_delete(&client, target, nonce).await;
        } else {
            best_effort_delete_matching(&client, request.id(), nonce).await;
        }
    }
    drop(client);
    drop(service);
    let shutdown = driver.shutdown().await;
    let runtime_clean = !super::path_exists(&executor_root).await?;
    drop(driver);
    let _ = tokio::fs::remove_file(&request_file).await;
    let _ = tokio::fs::remove_file(&ready_file).await;
    let mut evidence = exercise?;
    if let Err(error) = shutdown {
        return Err(format!(
            "{label} replacement driver shutdown failed: {error}"
        ));
    }
    evidence.cleanup_exact &= runtime_clean;
    if !evidence.cleanup_exact {
        return Err(format!(
            "{label} replacement retained restore runtime state"
        ));
    }
    Ok(evidence)
}

pub(super) async fn run_owner(
    init_executable: &Path,
    criu_executable: &Path,
    state_root: &Path,
    executor_parent: &Path,
    request_file: &Path,
    ready_file: &Path,
    crash_point: NativeLinuxCheckpointRestoreCrashPoint,
) -> Result<()> {
    let request: RestoreRequest = read_private_json_async(request_file, MAX_REQUEST_BYTES)
        .await
        .map_err(owner_error)?;
    let driver = Arc::new(
        NativeLinuxDriver::open_experimental_with_criu(
            executor_parent,
            init_executable,
            criu_executable,
        )
        .await?,
    );
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let fault = Arc::new(RestoreOwnerFault::new(
        crash_point,
        ready_file.to_path_buf(),
        request.context().operation_id.clone(),
    ));
    let fault_injector: Arc<dyn FaultInjector> = fault.clone();
    let service =
        HostRuntimeService::open_with_fault_injector(state_root, runtime_driver, fault_injector)
            .await?;
    let client = RuntimeClient::new(service.clone());
    fault.arm();
    let outcome = timeout(CHECKPOINT_TIMEOUT, client.restore(request.clone())).await;
    if crash_point == NativeLinuxCheckpointRestoreCrashPoint::AfterDriverCall {
        if let Ok(Err(error)) = &outcome {
            if fault.fired() && error.code == ErrorCode::Unavailable && error.retryable {
                fault.publish_ready()?;
                std::process::exit(OWNER_EXIT_CODE);
            }
        }
    }

    let reason = match outcome {
        Ok(Ok(response)) => {
            let target =
                ContainerTarget::exact(request.id().clone(), response.restored().generation);
            best_effort_delete(&client, &target, "unexpected-owner-return").await;
            "restore owner returned a response instead of terminating".to_string()
        }
        Ok(Err(error)) => format!("restore owner failed before its crash boundary: {error}"),
        Err(_) => "restore owner timed out before its crash boundary".to_string(),
    };
    drop(client);
    drop(service);
    let _ = driver.shutdown().await;
    Err(owner_error(reason))
}

async fn best_effort_delete_matching(client: &RuntimeClient, id: &ContainerId, nonce: &str) {
    let Ok(records) = client.list(ListRequest::default()).await else {
        return;
    };
    for record in records {
        if record.state.id() == id.as_str() {
            let target = ContainerTarget::exact(id.clone(), record.generation);
            best_effort_delete(client, &target, nonce).await;
        }
    }
}

fn process_is_live(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal zero does not mutate the target process and accepts every
    // positive PID. EPERM still proves that the process exists.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

async fn write_private_json_async<T>(path: &Path, value: &T) -> std::result::Result<(), String>
where
    T: Serialize,
{
    let path = path.to_path_buf();
    let encoded = canonical_json_bytes(value)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    tokio::task::spawn_blocking(move || write_private_bytes(&path, &encoded))
        .await
        .map_err(|error| format!("private JSON write task failed: {error}"))?
}

fn write_private_json<T>(path: &Path, value: &T) -> std::result::Result<(), String>
where
    T: Serialize,
{
    let encoded = canonical_json_bytes(value)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    write_private_bytes(path, &encoded)
}

fn write_private_bytes(path: &Path, encoded: &[u8]) -> std::result::Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("private JSON path has no parent: {}", path.display()))?;
    let pending = path.with_extension("pending");
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&pending).map_err(|error| {
        format!(
            "failed to create private JSON {}: {error}",
            pending.display()
        )
    })?;
    file.write_all(encoded)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            format!(
                "failed to commit private JSON {}: {error}",
                pending.display()
            )
        })?;
    std::fs::rename(&pending, path).map_err(|error| {
        format!(
            "failed to publish private JSON {} as {}: {error}",
            pending.display(),
            path.display()
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "failed to sync private JSON parent {}: {error}",
                parent.display()
            )
        })
}

async fn read_private_json_async<T>(path: &Path, max_bytes: u64) -> std::result::Result<T, String>
where
    T: DeserializeOwned + Send + 'static,
{
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || read_private_json(&path, max_bytes))
        .await
        .map_err(|error| format!("private JSON read task failed: {error}"))?
}

fn read_private_json<T>(path: &Path, max_bytes: u64) -> std::result::Result<T, String>
where
    T: DeserializeOwned,
{
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to open private JSON {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect private JSON {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(format!(
            "private JSON {} has invalid size {}; maximum is {max_bytes}",
            path.display(),
            metadata.len()
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut encoded)
        .map_err(|error| format!("failed to read private JSON {}: {error}", path.display()))?;
    serde_json::from_slice(&encoded)
        .map_err(|error| format!("failed to decode private JSON {}: {error}", path.display()))
}

fn owner_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message)
        .for_operation("native-linux-checkpoint-restore-owner")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn fault(
        root: &Path,
        crash_point: NativeLinuxCheckpointRestoreCrashPoint,
    ) -> RestoreOwnerFault {
        RestoreOwnerFault::new(
            crash_point,
            root.join("ready.json"),
            OperationId::new("restore-owner-operation").unwrap(),
        )
    }

    #[test]
    fn after_call_fault_is_armed_exactly_once_at_the_restore_boundary() {
        let temporary = tempdir().unwrap();
        let fault = fault(
            temporary.path(),
            NativeLinuxCheckpointRestoreCrashPoint::AfterDriverCall,
        );
        assert_eq!(
            fault.take_action(FaultPoint::DriverBoundary {
                operation: DriverOperation::Restore,
                stage: DriverBoundaryStage::AfterCall,
            }),
            RestoreOwnerAction::Continue
        );
        fault.arm();
        assert_eq!(
            fault.take_action(FaultPoint::DriverBoundary {
                operation: DriverOperation::RestoreValidation,
                stage: DriverBoundaryStage::AfterCall,
            }),
            RestoreOwnerAction::Continue
        );
        assert_eq!(
            fault.take_action(FaultPoint::DriverBoundary {
                operation: DriverOperation::Restore,
                stage: DriverBoundaryStage::AfterCall,
            }),
            RestoreOwnerAction::FailAfterDriverCall
        );
        assert_eq!(
            fault.take_action(FaultPoint::DriverBoundary {
                operation: DriverOperation::Restore,
                stage: DriverBoundaryStage::AfterCall,
            }),
            RestoreOwnerAction::Continue
        );
    }

    #[test]
    fn after_commit_fault_requires_the_fully_synced_restore_operation() {
        let temporary = tempdir().unwrap();
        let fault = fault(
            temporary.path(),
            NativeLinuxCheckpointRestoreCrashPoint::AfterHostCommit,
        );
        fault.arm();
        assert_eq!(
            fault.take_action(FaultPoint::DurableFile {
                mutation: DurableMutation::CompleteRestoreContainer,
                stage: FileCommitStage::ParentDirectorySynced,
            }),
            RestoreOwnerAction::Continue
        );
        assert_eq!(
            fault.take_action(FaultPoint::DurableFile {
                mutation: DurableMutation::CompleteRestoreOperation,
                stage: FileCommitStage::FileReplaced,
            }),
            RestoreOwnerAction::Continue
        );
        assert_eq!(
            fault.take_action(FaultPoint::DurableFile {
                mutation: DurableMutation::CompleteRestoreOperation,
                stage: FileCommitStage::ParentDirectorySynced,
            }),
            RestoreOwnerAction::ExitAfterHostCommit
        );
        assert_eq!(
            fault.take_action(FaultPoint::DurableFile {
                mutation: DurableMutation::CompleteRestoreOperation,
                stage: FileCommitStage::ParentDirectorySynced,
            }),
            RestoreOwnerAction::Continue
        );
    }

    #[tokio::test]
    async fn owner_evidence_is_atomically_written_and_bounded_on_reopen() {
        let temporary = tempdir().unwrap();
        let fault = fault(
            temporary.path(),
            NativeLinuxCheckpointRestoreCrashPoint::AfterDriverCall,
        );
        fault.publish_ready().unwrap();
        let observed: RestoreOwnerExitEvidence =
            read_private_json_async(&fault.ready_file, MAX_EVIDENCE_BYTES)
                .await
                .unwrap();
        assert_eq!(observed, fault.evidence);
        assert!(!temporary.path().join("ready.pending").exists());
    }
}
