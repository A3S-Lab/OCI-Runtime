use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, DriverKind, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointRequest, ContainerId, ContainerOperationRequest,
    ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    ExitStatus, IoMode, IsolationRequest, KillRequest, OciBundle, OperationContext, OperationId,
    ProcessIo, RestoreRequest, Result, RuntimeClient, RuntimeOperation, Signal, StartRequest,
    StateRequest, WaitRequest,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::time::{sleep, timeout, Instant};

use super::filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, remove_marker,
    unique_nonce, MARKER_NAME,
};
use crate::fault::{DriverBoundaryStage, DriverOperation, FaultInjector, FaultPoint};
use crate::{
    HostRuntimeService, NativeLinuxCheckpointSmokeReport, NativeLinuxDriver, RuntimeDriver,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(5 * 60 + 15);
const MARKER_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const PREEXISTING_CONTENT: &[u8] = b"caller-owned-checkpoint-destination\n";
const CHECKPOINT_STATE_DIRECTORY: &str = ".a3s-oci-native-checkpoint-v1";

#[derive(Debug)]
struct LifecycleAfterCallFault {
    artifact_path: PathBuf,
    checkpoint_armed: AtomicBool,
    checkpoint_fired: AtomicBool,
    restore_armed: AtomicBool,
    restore_fired: AtomicBool,
}

impl LifecycleAfterCallFault {
    fn new(artifact_path: PathBuf) -> Self {
        Self {
            artifact_path,
            checkpoint_armed: AtomicBool::new(false),
            checkpoint_fired: AtomicBool::new(false),
            restore_armed: AtomicBool::new(false),
            restore_fired: AtomicBool::new(false),
        }
    }

    fn arm_checkpoint(&self) {
        self.checkpoint_armed.store(true, Ordering::SeqCst);
    }

    fn checkpoint_fired(&self) -> bool {
        self.checkpoint_fired.load(Ordering::SeqCst)
    }

    fn arm_restore(&self) {
        self.restore_armed.store(true, Ordering::SeqCst);
    }

    fn restore_fired(&self) -> bool {
        self.restore_fired.load(Ordering::SeqCst)
    }
}

impl FaultInjector for LifecycleAfterCallFault {
    fn check(&self, point: FaultPoint) -> Result<()> {
        if matches!(
            point,
            FaultPoint::DriverBoundary {
                operation: DriverOperation::Checkpoint,
                stage: DriverBoundaryStage::AfterCall,
            }
        ) && self.checkpoint_armed.load(Ordering::SeqCst)
            && self.artifact_path.is_file()
            && !self.checkpoint_fired.swap(true, Ordering::SeqCst)
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "injected one-shot failure after native checkpoint driver return",
            )
            .for_operation("native-linux-checkpoint-smoke")
            .retryable(true));
        }
        if matches!(
            point,
            FaultPoint::DriverBoundary {
                operation: DriverOperation::Restore,
                stage: DriverBoundaryStage::AfterCall,
            }
        ) && self.restore_armed.load(Ordering::SeqCst)
            && !self.restore_fired.swap(true, Ordering::SeqCst)
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "injected one-shot failure after native restore driver return",
            )
            .for_operation("native-linux-restore-smoke")
            .retryable(true));
        }
        Ok(())
    }
}

pub(super) async fn run(
    init_executable: &Path,
    criu_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
    source_revision: String,
) -> NativeLinuxCheckpointSmokeReport {
    let mut report =
        NativeLinuxCheckpointSmokeReport::initial(HostPlatform::Linux, source_revision);
    let work_parent = match canonical_directory(work_parent, "checkpoint smoke work parent").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let init_executable = match canonical_file(init_executable, "a3s-oci-agent").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let criu_executable = match canonical_file(criu_executable, "CRIU executable").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle = match OciBundle::load(&bundle_directory).await {
        Ok(bundle) => bundle,
        Err(error) => return failed(report, format!("failed to load OCI bundle: {error}")),
    };
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let marker = rootfs.join(MARKER_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing checkpoint smoke marker: {}",
                    marker.display()
                ),
            )
        }
        Err(reason) => return failed(report, reason),
    }

    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let session_root = work_parent.join(format!("a3s-oci-native-checkpoint-{nonce}"));
    if let Err(reason) = create_private_directory(&session_root).await {
        return failed(report, reason);
    }
    let executor_parent = session_root.join("executor");
    if let Err(reason) = create_private_directory(&executor_parent).await {
        return cleanup_session(report, &session_root, &marker, reason).await;
    }
    let driver = match NativeLinuxDriver::open_experimental_with_criu(
        &executor_parent,
        &init_executable,
        &criu_executable,
    )
    .await
    {
        Ok(driver) => Arc::new(driver),
        Err(error) => {
            return cleanup_session(
                report,
                &session_root,
                &marker,
                format!("failed to open CRIU-backed native driver: {error}"),
            )
            .await
        }
    };
    let executor_root = driver.executor_root().to_path_buf();
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let fault = Arc::new(LifecycleAfterCallFault::new(
        session_root.join("checkpoint.bin"),
    ));
    let fault_injector: Arc<dyn FaultInjector> = fault.clone();
    let service = match HostRuntimeService::open_with_fault_injector(
        session_root.join("state"),
        runtime_driver,
        fault_injector,
    )
    .await
    {
        Ok(service) => service,
        Err(error) => {
            let reason = format!("failed to open checkpoint Host service: {error}");
            let _ = driver.shutdown().await;
            return cleanup_session(report, &session_root, &marker, reason).await;
        }
    };
    let client = RuntimeClient::new(service.clone());
    let mut cleanup_target = None;
    let exercise = exercise(
        &client,
        &bundle,
        &session_root,
        &executor_parent,
        &marker,
        &nonce,
        &fault,
        &mut cleanup_target,
        &mut report,
    )
    .await;
    if exercise.is_err() {
        if let Some(target) = cleanup_target.as_ref() {
            best_effort_delete(&client, target, &nonce).await;
        }
    }
    drop(client);
    drop(service);

    if let Err(error) = driver.shutdown().await {
        append_reason(
            &mut report,
            format!("native checkpoint executor shutdown failed: {error}"),
        );
    }
    match path_exists(&executor_root).await {
        Ok(exists) => report.executor_runtime_clean = !exists,
        Err(reason) => append_reason(&mut report, reason),
    }
    drop(driver);
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    match remove_marker(&marker).await {
        Ok(()) => {}
        Err(reason) => append_reason(&mut report, reason),
    }
    match tokio::fs::remove_dir_all(&session_root).await {
        Ok(()) => match path_exists(&session_root).await {
            Ok(exists) => report.session_root_clean = !exists,
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove checkpoint smoke session {}: {error}",
                session_root.display()
            ),
        ),
    }
    if report.is_success_except_status() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    client: &RuntimeClient,
    bundle: &OciBundle,
    session_root: &Path,
    executor_parent: &Path,
    marker: &Path,
    nonce: &str,
    fault: &LifecycleAfterCallFault,
    cleanup_target: &mut Option<ContainerTarget>,
    report: &mut NativeLinuxCheckpointSmokeReport,
) -> std::result::Result<(), String> {
    let features = call("features", CALL_TIMEOUT, client.features()).await?;
    report.checkpoint_advertised = features.operations.contains(&RuntimeOperation::Checkpoint);
    report.restore_advertised = features.operations.contains(&RuntimeOperation::Restore);
    let capability = features
        .drivers
        .driver(DriverKind::NativeLinux)
        .ok_or_else(|| "checkpoint feature inventory omits Native Linux".to_string())?;
    report.driver_evidence = capability.evidence.clone();
    if !report.checkpoint_advertised || !report.restore_advertised {
        return Err("CRIU-backed driver did not expose Checkpoint and Restore together".into());
    }

    let id = ContainerId::new(format!("checkpoint-{nonce}"))
        .map_err(|error| format!("failed to construct checkpoint container ID: {error}"))?;
    let attachments = CreateAttachments::from_bundle(bundle, configured_init_io(bundle))
        .map_err(|error| format!("failed to derive checkpoint attachments: {error}"))?;
    let created = call(
        "create checkpoint source",
        CALL_TIMEOUT,
        client.create(CreateRequest {
            context: operation(nonce, "create")?,
            id: id.clone(),
            bundle: bundle.clone(),
            isolation: IsolationRequest::SharedHostKernel,
            attachments: attachments.clone(),
        }),
    )
    .await?;
    if *created.state.status() != ContainerState::Created {
        return Err("checkpoint source create did not preserve the OCI created barrier".into());
    }
    let target = ContainerTarget::exact(id.clone(), created.generation);
    *cleanup_target = Some(target.clone());
    let started = call(
        "start checkpoint source",
        CALL_TIMEOUT,
        client.start(StartRequest {
            context: operation(nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    report.lifecycle_started = *started.state.status() == ContainerState::Running;
    wait_for_marker(marker).await?;
    let paused = call(
        "pause checkpoint source",
        CALL_TIMEOUT,
        client.pause(ContainerOperationRequest {
            context: operation(nonce, "pause")?,
            target: target.clone(),
        }),
    )
    .await?;
    report.paused_source_observed = paused.is_paused();
    if !report.paused_source_observed {
        return Err("checkpoint source was not durably paused".into());
    }

    let preexisting_path = session_root.join("preexisting.bin");
    tokio::fs::write(&preexisting_path, PREEXISTING_CONTENT)
        .await
        .map_err(|error| format!("failed to write preexisting checkpoint fixture: {error}"))?;
    let preexisting = CheckpointRequest::new(
        operation(nonce, "checkpoint-preexisting")?,
        target.clone(),
        CheckpointArtifactPath::new(preexisting_path.clone())
            .map_err(|error| format!("invalid preexisting checkpoint path: {error}"))?,
    )
    .map_err(|error| format!("failed to construct preexisting checkpoint request: {error}"))?;
    let error = match timeout(CALL_TIMEOUT, client.checkpoint(preexisting))
        .await
        .map_err(|_| "preexisting checkpoint rejection timed out".to_string())?
    {
        Err(error) => error,
        Ok(_) => return Err("preexisting checkpoint destination was overwritten".into()),
    };
    report.preexisting_destination_rejected = error.code == ErrorCode::AlreadyExists;
    report.preexisting_destination_preserved = tokio::fs::read(&preexisting_path)
        .await
        .map_err(|error| format!("failed to reread preexisting checkpoint fixture: {error}"))?
        == PREEXISTING_CONTENT;
    if !report.preexisting_destination_rejected || !report.preexisting_destination_preserved {
        return Err("checkpoint did not preserve a preexisting destination exactly".into());
    }

    let artifact_path = session_root.join("checkpoint.bin");
    let request = CheckpointRequest::new(
        operation(nonce, "checkpoint")?,
        target.clone(),
        CheckpointArtifactPath::new(artifact_path.clone())
            .map_err(|error| format!("invalid checkpoint artifact path: {error}"))?,
    )
    .map_err(|error| format!("failed to construct checkpoint request: {error}"))?;
    fault.arm_checkpoint();
    let first_error = match timeout(CHECKPOINT_TIMEOUT, client.checkpoint(request.clone()))
        .await
        .map_err(|_| "faulted checkpoint attempt timed out".to_string())?
    {
        Err(error) => error,
        Ok(_) => return Err("checkpoint Host fault did not interrupt the first response".into()),
    };
    report.driver_after_call_fault_injected = fault.checkpoint_fired()
        && first_error.code == ErrorCode::Unavailable
        && first_error.retryable;
    if !report.driver_after_call_fault_injected {
        return Err(format!(
            "native checkpoint driver failed before the injected Host boundary: {first_error}"
        ));
    }
    let before_replay = artifact_identity(&artifact_path).await?;
    report.artifact_published_before_host_commit = before_replay.1 > 0;

    let response = call(
        "resume checkpoint through driver journal",
        CHECKPOINT_TIMEOUT,
        client.checkpoint(request.clone()),
    )
    .await?;
    report.driver_replay_completed_host_commit = response.source().is_paused();
    let host_replay = call(
        "replay committed checkpoint",
        CALL_TIMEOUT,
        client.checkpoint(request),
    )
    .await?;
    report.host_replay_exact = host_replay == response;
    let after_replay = artifact_identity(&artifact_path).await?;
    report.artifact_bytes_unchanged_across_replay = before_replay == after_replay;
    let reference = response.reference().clone();
    report.artifact_digest = Some(reference.artifact_digest().to_string());
    report.artifact_size_bytes = Some(reference.artifact_size_bytes());
    report.artifact_digest_verified = after_replay.0 == reference.artifact_digest().as_str()
        && after_replay.1 == reference.artifact_size_bytes();
    let observed = call(
        "state after checkpoint replay",
        CALL_TIMEOUT,
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    report.source_remained_paused = observed.is_paused();
    if !report.artifact_digest_verified || !report.source_remained_paused {
        return Err("checkpoint replay changed the artifact or thawed its source".into());
    }

    let resumed = call(
        "resume checkpoint source",
        CALL_TIMEOUT,
        client.resume(ContainerOperationRequest {
            context: operation(nonce, "resume")?,
            target: target.clone(),
        }),
    )
    .await?;
    report.source_resume_succeeded = !resumed.is_paused();
    call(
        "kill checkpoint source",
        CALL_TIMEOUT,
        client.kill(KillRequest {
            context: operation(nonce, "kill")?,
            target: target.clone(),
            signal: Signal::new(libc::SIGKILL)
                .map_err(|error| format!("failed to construct SIGKILL: {error}"))?,
            all: true,
        }),
    )
    .await?;
    call(
        "wait checkpoint source",
        CALL_TIMEOUT,
        client.wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(10_000),
        }),
    )
    .await?;
    call(
        "delete checkpoint source",
        CALL_TIMEOUT,
        client.delete(DeleteRequest {
            context: operation(nonce, "delete")?,
            target: target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await?;
    *cleanup_target = None;
    report.artifact_survived_source_delete = path_exists(&artifact_path).await?;

    let restore_request = RestoreRequest::new(
        operation(nonce, "restore")?,
        id,
        bundle.clone(),
        CheckpointArtifactPath::new(artifact_path.clone())
            .map_err(|error| format!("invalid restore artifact path: {error}"))?,
        IsolationRequest::SharedHostKernel,
        attachments,
        reference,
    )
    .map_err(|error| format!("failed to construct restore request: {error}"))?;
    fault.arm_restore();
    let first_restore_error =
        match timeout(CHECKPOINT_TIMEOUT, client.restore(restore_request.clone()))
            .await
            .map_err(|_| "faulted restore attempt timed out".to_string())?
        {
            Err(error) => error,
            Ok(_) => return Err("restore Host fault did not interrupt the first response".into()),
        };
    report.restore_after_call_fault_injected = fault.restore_fired()
        && first_restore_error.code == ErrorCode::Unavailable
        && first_restore_error.retryable;
    if !report.restore_after_call_fault_injected {
        return Err(format!(
            "native restore driver failed before the injected Host boundary: {first_restore_error}"
        ));
    }
    let restored = call(
        "resume restore through driver replay",
        CHECKPOINT_TIMEOUT,
        client.restore(restore_request.clone()),
    )
    .await?;
    report.driver_restore_replay_completed_host_commit = restored.restored().is_paused();
    let restored_target =
        ContainerTarget::exact(restore_request.id().clone(), restored.restored().generation);
    *cleanup_target = Some(restored_target.clone());
    let restore_replay = call(
        "replay committed restore",
        CALL_TIMEOUT,
        client.restore(restore_request),
    )
    .await?;
    report.restore_host_replay_exact = restore_replay == restored;
    report.restored_generation_newer = restored.restored().generation > created.generation;
    report.restored_running_paused = *restored.restored().state.status() == ContainerState::Running
        && restored.restored().is_paused();
    let restored_state = call(
        "state after restore replay",
        CALL_TIMEOUT,
        client.state(StateRequest {
            target: restored_target.clone(),
        }),
    )
    .await?;
    report.restored_state_exact = restored_state == *restored.restored();
    report.artifact_bytes_unchanged_across_restore =
        artifact_identity(&artifact_path).await? == after_replay;
    if !report.restore_host_replay_exact
        || !report.restored_generation_newer
        || !report.restored_running_paused
        || !report.restored_state_exact
        || !report.artifact_bytes_unchanged_across_restore
    {
        return Err("restore replay changed its paused generation or immutable artifact".into());
    }

    let restored_resumed = call(
        "resume restored container",
        CALL_TIMEOUT,
        client.resume(ContainerOperationRequest {
            context: operation(nonce, "restore-resume")?,
            target: restored_target.clone(),
        }),
    )
    .await?;
    report.restored_resume_succeeded = !restored_resumed.is_paused();
    call(
        "kill restored container",
        CALL_TIMEOUT,
        client.kill(KillRequest {
            context: operation(nonce, "restore-kill")?,
            target: restored_target.clone(),
            signal: Signal::new(libc::SIGKILL)
                .map_err(|error| format!("failed to construct restore SIGKILL: {error}"))?,
            all: true,
        }),
    )
    .await?;
    let restored_exit = call(
        "wait restored container",
        CALL_TIMEOUT,
        client.wait(WaitRequest {
            target: restored_target.clone(),
            timeout_ms: Some(10_000),
        }),
    )
    .await?;
    report.restored_exit_status_exact = restored_exit
        == ExitStatus::signaled(libc::SIGKILL, false)
            .map_err(|error| format!("failed to construct restored exit status: {error}"))?;
    call(
        "delete restored container",
        CALL_TIMEOUT,
        client.delete(DeleteRequest {
            context: operation(nonce, "restore-delete")?,
            target: restored_target,
            mode: DeleteMode::Force,
        }),
    )
    .await?;
    *cleanup_target = None;
    report.artifact_survived_restored_delete = path_exists(&artifact_path).await?;
    let operations = executor_parent
        .join(CHECKPOINT_STATE_DIRECTORY)
        .join("operations");
    let staging = executor_parent
        .join(CHECKPOINT_STATE_DIRECTORY)
        .join("staging");
    report.driver_journal_acknowledged = directory_is_empty(&operations).await?;
    report.unpublished_partials_absent =
        directory_is_empty(&staging).await? && no_pending_entries(session_root).await?;
    if !report.driver_journal_acknowledged || !report.unpublished_partials_absent {
        return Err(
            "checkpoint driver retained an acknowledged journal or unpublished partial".into(),
        );
    }
    Ok(())
}

fn configured_init_io(bundle: &OciBundle) -> ProcessIo {
    let mode = if bundle
        .spec()
        .process()
        .as_ref()
        .is_some_and(|process| process.terminal().unwrap_or(false))
    {
        IoMode::Terminal
    } else {
        IoMode::Null
    };
    ProcessIo {
        stdin: mode,
        stdout: mode,
        stderr: mode,
        terminal_size: None,
    }
}

async fn canonical_file(path: &Path, label: &str) -> std::result::Result<PathBuf, String> {
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    let metadata = tokio::fs::symlink_metadata(&canonical)
        .await
        .map_err(|error| format!("failed to inspect {label} {}: {error}", canonical.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} is not a real file: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

async fn wait_for_marker(marker: &Path) -> std::result::Result<(), String> {
    let deadline = Instant::now() + MARKER_TIMEOUT;
    loop {
        if path_exists(marker).await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for checkpoint source marker {}",
                marker.display()
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn artifact_identity(path: &Path) -> std::result::Result<(String, u64), String> {
    let mut file = tokio::fs::File::open(path).await.map_err(|error| {
        format!(
            "failed to open checkpoint artifact {}: {error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().await.map_err(|error| {
        format!(
            "failed to inspect checkpoint artifact {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "checkpoint artifact is not a positive regular file: {}",
            path.display()
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| format!("failed to hash checkpoint artifact: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok((format!("sha256:{:x}", digest.finalize()), metadata.len()))
}

async fn directory_is_empty(path: &Path) -> std::result::Result<bool, String> {
    let mut entries = tokio::fs::read_dir(path)
        .await
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    entries
        .next_entry()
        .await
        .map(|entry| entry.is_none())
        .map_err(|error| format!("failed to read {}: {error}", path.display()))
}

async fn no_pending_entries(path: &Path) -> std::result::Result<bool, String> {
    let mut entries = tokio::fs::read_dir(path)
        .await
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?
    {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(".pending"))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn best_effort_delete(client: &RuntimeClient, target: &ContainerTarget, nonce: &str) {
    if let Ok(context) = operation(nonce, "cleanup-kill") {
        if let Ok(signal) = Signal::new(libc::SIGKILL) {
            let _ = timeout(
                CALL_TIMEOUT,
                client.kill(KillRequest {
                    context,
                    target: target.clone(),
                    signal,
                    all: true,
                }),
            )
            .await;
        }
    }
    if let Ok(context) = operation(nonce, "cleanup-delete") {
        let _ = timeout(
            CALL_TIMEOUT,
            client.delete(DeleteRequest {
                context,
                target: target.clone(),
                mode: DeleteMode::Force,
            }),
        )
        .await;
    }
}

async fn call<T>(
    label: &str,
    duration: Duration,
    future: impl std::future::Future<Output = Result<T>>,
) -> std::result::Result<T, String> {
    timeout(duration, future)
        .await
        .map_err(|_| format!("{label} timed out after {} seconds", duration.as_secs()))?
        .map_err(|error| format!("{label} failed: {error}"))
}

fn operation(nonce: &str, suffix: &str) -> std::result::Result<OperationContext, String> {
    OperationId::new(format!("checkpoint-{nonce}-{suffix}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct {suffix} operation ID: {error}"))
}

async fn cleanup_session(
    mut report: NativeLinuxCheckpointSmokeReport,
    session_root: &Path,
    marker: &Path,
    reason: impl Into<String>,
) -> NativeLinuxCheckpointSmokeReport {
    append_reason(&mut report, reason);
    let _ = remove_marker(marker).await;
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => report.session_root_clean = true,
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove checkpoint smoke session {}: {error}",
                session_root.display()
            ),
        ),
    }
    report
}

fn failed(
    mut report: NativeLinuxCheckpointSmokeReport,
    reason: impl Into<String>,
) -> NativeLinuxCheckpointSmokeReport {
    append_reason(&mut report, reason);
    report
}

fn append_reason(report: &mut NativeLinuxCheckpointSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) => format!("{existing}; {reason}"),
        None => reason,
    });
}

trait ReportStatus {
    fn is_success_except_status(&self) -> bool;
}

impl ReportStatus for NativeLinuxCheckpointSmokeReport {
    fn is_success_except_status(&self) -> bool {
        let mut report = self.clone();
        report.status = CapabilityStatus::Available;
        report.reason = None;
        report.is_success()
    }
}
