use std::{io, path::Path};

use a3s_oci_agent::LinuxExecutor;
use a3s_oci_agent_protocol::{AgentCreateRequest, AgentState};
use a3s_oci_core::{DriverKind, HostPlatform, IsolationClass};
use a3s_oci_sdk::{
    canonical_json_bytes, CheckpointDigest, CheckpointFormat, CheckpointReference, ContainerId,
    ContainerTarget, ErrorCode, OperationId, Result, RuntimeArtifact,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{DriverRestoreRequest, DriverRestoreValidationRequest};

use super::{
    append_failure,
    artifact::{self, BuiltArtifact},
    checkpoint_error, io_error,
    journal::{self, RestoreJournalRecord},
    publication::ArtifactDestination,
    tool::{self, CriuRestoreSpawner, CriuTool},
    NativeCriuCheckpoint,
};

const RESTORE_JOURNAL_REQUEST_SCHEMA_V1: &str = "a3s.oci.native-restore-request.v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreRequestFingerprint<'a> {
    schema_version: &'static str,
    context: &'a a3s_oci_sdk::OperationContext,
    target: &'a ContainerTarget,
    bundle: &'a a3s_oci_sdk::OciBundle,
    artifact_path: &'a a3s_oci_sdk::CheckpointArtifactPath,
    isolation: &'a a3s_oci_sdk::IsolationRequest,
    io: &'a a3s_oci_sdk::ProcessIo,
    attachment_contract: &'a a3s_oci_sdk::CreateAttachments,
    tee_launch: &'a Option<a3s_oci_sdk::TeeLaunchRequest>,
    reference: &'a CheckpointReference,
    runtime_artifact: &'a RuntimeArtifact,
    agent_request: &'a AgentCreateRequest,
}

pub(crate) enum NativeRestoreRecovery {
    Pending,
    Recreated(AgentState),
}

impl NativeCriuCheckpoint {
    pub(crate) async fn validate_restore_artifact(
        &self,
        request: &DriverRestoreValidationRequest,
    ) -> Result<()> {
        validate_restore_stack(
            &request.reference,
            &request.runtime_artifact,
            &self.driver_build_digest,
            &self.format,
        )?;
        let artifact = self.open_external_artifact(&request.artifact_path).await?;
        let built = artifact::validate_external(
            artifact,
            request.reference.artifact_digest().clone(),
            request.reference.artifact_size_bytes(),
        )
        .await?;
        self.require_restore_manifest(&built, &request.reference)
    }

    pub(crate) async fn restore(
        &self,
        executor: &LinuxExecutor,
        request: &DriverRestoreRequest,
        agent_request: AgentCreateRequest,
    ) -> Result<AgentState> {
        validate_restore_stack(
            &request.reference,
            &request.runtime_artifact,
            &self.driver_build_digest,
            &self.format,
        )?;
        validate_restore_request_v1(request)?;
        let operation_id = request.context.operation_id.clone();
        let request_digest = restore_request_digest(request, &agent_request)?;
        let operation_lock = self.operation_lock(&operation_id).await;
        let _guard = operation_lock.lock().await;
        let mut record = match self.journals.load_restore(&operation_id).await? {
            Some(record) => {
                record.validate_request(
                    &operation_id,
                    &request_digest,
                    &agent_request,
                    &request.artifact_path,
                    &request.reference,
                )?;
                record
            }
            None => {
                let record = RestoreJournalRecord::allocated(
                    request_digest,
                    agent_request.clone(),
                    request.artifact_path.clone(),
                    request.reference.clone(),
                )?;
                self.journals.store_restore(&record).await?;
                record
            }
        };
        let (stage, manifest) = match self.prepare_restore_stage(&mut record, request, true).await {
            Ok(prepared) => prepared,
            Err(mut error) => {
                if let Err(rollback) = executor
                    .rollback_restore(&request.target, request.bundle.config_digest())
                    .await
                {
                    append_failure(&mut error, "restored generation rollback", &rollback);
                } else if let Err(cleanup) = self.cleanup_restore_operation(&operation_id).await {
                    append_failure(&mut error, "restore journal cleanup", &cleanup);
                }
                return Err(error);
            }
        };
        if let Err(mut error) = reset_restore_work(stage.work()).await {
            if let Err(rollback) = executor
                .rollback_restore(&request.target, request.bundle.config_digest())
                .await
            {
                append_failure(&mut error, "restored generation rollback", &rollback);
            } else if let Err(cleanup) = self.cleanup_restore_operation(&operation_id).await {
                append_failure(&mut error, "restore journal cleanup", &cleanup);
            }
            return Err(error);
        }
        let spawner = CriuRestoreSpawner::new(
            &self.tool,
            stage.images(),
            stage.work(),
            manifest.external_mounts(),
        );
        let mut result = executor.restore_with(agent_request, &spawner).await;
        if let Err(error) = &mut result {
            let (log, truncated) = tool::read_log_bounded(&stage.work().join("restore.log")).await;
            error.message = format!(
                "{}; CRIU restore log={:?}; log_truncated={truncated}",
                error.message,
                log.trim()
            );
        }
        match result {
            Ok(state) => {
                if let Err(mut error) = record.mark_restored(manifest, state.clone()) {
                    if let Err(rollback) = executor
                        .rollback_restore(&request.target, request.bundle.config_digest())
                        .await
                    {
                        append_failure(&mut error, "restored generation rollback", &rollback);
                    } else if let Err(cleanup) = self.cleanup_restore_operation(&operation_id).await
                    {
                        append_failure(&mut error, "restore journal cleanup", &cleanup);
                    }
                    return Err(error);
                }
                if let Err(mut error) = self.journals.store_restore(&record).await {
                    if let Err(rollback) = executor
                        .rollback_restore(&request.target, request.bundle.config_digest())
                        .await
                    {
                        append_failure(&mut error, "restored generation rollback", &rollback);
                    } else if let Err(cleanup) = self.cleanup_restore_operation(&operation_id).await
                    {
                        append_failure(&mut error, "restore journal cleanup", &cleanup);
                    }
                    return Err(error);
                }
                Ok(state)
            }
            Err(mut error) => {
                if let Err(rollback) = executor
                    .rollback_restore(&request.target, request.bundle.config_digest())
                    .await
                {
                    append_failure(&mut error, "restored generation rollback", &rollback);
                } else if let Err(cleanup) = self.cleanup_restore_operation(&operation_id).await {
                    append_failure(&mut error, "restore journal cleanup", &cleanup);
                }
                Err(error)
            }
        }
    }

    pub(crate) async fn recover_restore(
        &self,
        executor: &LinuxExecutor,
        durable: &a3s_oci_sdk::ContainerRecord,
    ) -> Result<Option<NativeRestoreRecovery>> {
        let target = ContainerTarget::exact(
            ContainerId::new(durable.state.id().to_string())?,
            durable.generation,
        );
        let Some(found) = self.journals.find_restore(&target).await? else {
            return Ok(None);
        };
        let operation_id = found.operation_id().clone();
        let operation_lock = self.operation_lock(&operation_id).await;
        let _guard = operation_lock.lock().await;
        let mut record = self
            .journals
            .load_restore(&operation_id)
            .await?
            .ok_or_else(|| {
                checkpoint_error(
                    ErrorCode::Conflict,
                    "native restore journal disappeared during recovery",
                )
            })?;
        self.validate_durable_restore(&record, durable)?;

        if let Some(manifest) = record.manifest().cloned() {
            record.mark_prepared(manifest);
            self.journals.store_restore(&record).await?;
        }
        if let Some(tombstone) = executor
            .recover_stale_generation(&target, &durable.config_digest, *durable.state.pid())
            .await?
        {
            executor.delete_stale_generation(&tombstone).await?;
        }

        match *durable.state.status() {
            a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating => {
                Ok(Some(NativeRestoreRecovery::Pending))
            }
            a3s_oci_sdk::oci_spec::runtime::ContainerState::Running if durable.is_paused() => {
                let manifest = record.manifest().cloned().ok_or_else(|| {
                    checkpoint_error(
                        ErrorCode::FailedPrecondition,
                        "completed native restore has no retained prepared image manifest",
                    )
                })?;
                let stage = self
                    .journals
                    .open_restore_stage(&operation_id)
                    .await?
                    .ok_or_else(|| {
                        checkpoint_error(
                            ErrorCode::FailedPrecondition,
                            "completed native restore lost its retained image stage",
                        )
                    })?;
                manifest.validate_retained_images(stage.images())?;
                self.require_restore_artifact_manifest(&manifest, record.reference())?;
                reset_restore_work(stage.work()).await?;
                let mut agent_request = record.agent_request().clone();
                agent_request.context.deadline_unix_ms = None;
                let spawner = CriuRestoreSpawner::new(
                    &self.tool,
                    stage.images(),
                    stage.work(),
                    manifest.external_mounts(),
                );
                let state = executor.restore_with(agent_request, &spawner).await?;
                record.mark_restored(manifest, state.clone())?;
                if let Err(mut error) = self.journals.store_restore(&record).await {
                    if let Err(rollback) = executor
                        .rollback_restore(&target, record.agent_request().bundle.config_digest())
                        .await
                    {
                        append_failure(&mut error, "recreated restore rollback", &rollback);
                    }
                    return Err(error);
                }
                Ok(Some(NativeRestoreRecovery::Recreated(state)))
            }
            status => Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native restore journal cannot recover durable container {} while {status} with paused={}",
                    durable.state.id(),
                    durable.is_paused()
                ),
            )),
        }
    }

    async fn prepare_restore_stage(
        &self,
        record: &mut RestoreJournalRecord,
        request: &DriverRestoreRequest,
        allow_reextract: bool,
    ) -> Result<(
        journal::StageDirectory,
        artifact::CheckpointArtifactManifest,
    )> {
        if let Some(manifest) = record.manifest().cloned() {
            match self
                .journals
                .open_restore_stage(record.operation_id())
                .await?
            {
                Some(stage) => {
                    manifest.validate_retained_images(stage.images())?;
                    self.require_restore_artifact_manifest(&manifest, &request.reference)?;
                    return Ok((stage, manifest));
                }
                None if !allow_reextract => {
                    return Err(checkpoint_error(
                        ErrorCode::FailedPrecondition,
                        "native restore lost its retained prepared image stage",
                    ));
                }
                None => record.mark_allocated(),
            }
        }

        self.journals.store_restore(record).await?;
        let stage = self
            .journals
            .create_restore_stage(record.operation_id())
            .await?;
        let artifact = self.open_external_artifact(record.artifact_path()).await?;
        let built = artifact::extract_external(
            artifact,
            request.reference.artifact_digest().clone(),
            request.reference.artifact_size_bytes(),
            stage.images().to_path_buf(),
        )
        .await?;
        self.require_restore_manifest(&built, &request.reference)?;
        let manifest = built.manifest;
        record.mark_prepared(manifest.clone());
        self.journals.store_restore(record).await?;
        Ok((stage, manifest))
    }

    pub(super) async fn cleanup_restore_operation(&self, operation_id: &OperationId) -> Result<()> {
        self.journals.cleanup_restore_stage(operation_id).await?;
        self.journals.remove_restore(operation_id).await
    }

    fn validate_durable_restore(
        &self,
        record: &RestoreJournalRecord,
        durable: &a3s_oci_sdk::ContainerRecord,
    ) -> Result<()> {
        validate_restore_stack(
            record.reference(),
            record.reference().compatibility().runtime_artifact(),
            &self.driver_build_digest,
            &self.format,
        )?;
        if durable.driver != DriverKind::NativeLinux
            || durable.isolation != IsolationClass::SharedHostKernel
            || record.target().id.as_str() != durable.state.id()
            || record.target().generation != Some(durable.generation)
            || durable.config_digest != record.agent_request().bundle.config_digest()
            || durable.attachments_digest.as_deref()
                != Some(record.reference().source_attachments_digest().as_str())
        {
            return Err(checkpoint_error(
                ErrorCode::Conflict,
                "durable restored generation differs from its native restore journal",
            ));
        }
        Ok(())
    }

    async fn open_external_artifact(
        &self,
        path: &a3s_oci_sdk::CheckpointArtifactPath,
    ) -> Result<std::fs::File> {
        ArtifactDestination::open(path)
            .await?
            .open_final()
            .await?
            .ok_or_else(|| {
                checkpoint_error(
                    ErrorCode::NotFound,
                    format!(
                        "checkpoint artifact does not exist: {}",
                        path.as_path().display()
                    ),
                )
            })
    }

    fn require_restore_manifest(
        &self,
        built: &BuiltArtifact,
        reference: &CheckpointReference,
    ) -> Result<()> {
        self.require_restore_artifact_manifest(&built.manifest, reference)
    }

    fn require_restore_artifact_manifest(
        &self,
        manifest: &artifact::CheckpointArtifactManifest,
        reference: &CheckpointReference,
    ) -> Result<()> {
        if manifest.source() != reference.source()
            || manifest.source_config_digest() != reference.source_config_digest()
            || manifest.source_attachments_digest() != reference.source_attachments_digest()
            || manifest.compatibility() != reference.compatibility()
            || manifest.criu() != &self.tool.identity()
            || manifest.dump_options()
                != CriuTool::dump_options(
                    manifest.cgroup_path(),
                    manifest
                        .external_mounts()
                        .iter()
                        .map(|mount| (mount.name(), mount.mountpoint())),
                )?
        {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                "checkpoint artifact manifest does not match its immutable reference or current CRIU backend",
            ));
        }
        Ok(())
    }
}

fn validate_restore_stack(
    reference: &CheckpointReference,
    runtime_artifact: &RuntimeArtifact,
    driver_build_digest: &CheckpointDigest,
    format: &CheckpointFormat,
) -> Result<()> {
    let compatibility = reference.compatibility();
    if compatibility.driver() != DriverKind::NativeLinux
        || compatibility.isolation() != IsolationClass::SharedHostKernel
        || compatibility.platform() != HostPlatform::Linux
        || compatibility.architecture() != std::env::consts::ARCH
        || compatibility.runtime_artifact() != runtime_artifact
        || compatibility.driver_build_digest() != driver_build_digest
        || compatibility.format() != format
    {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            "checkpoint reference is incompatible with the current native CRIU restore stack",
        ));
    }
    Ok(())
}

fn validate_restore_request_v1(request: &DriverRestoreRequest) -> Result<()> {
    if request.isolation.class() != IsolationClass::SharedHostKernel
        || request.tee_launch.is_some()
        || request.bundle.config_digest() != request.reference.source_config_digest().as_str()
        || request.attachment_contract.digest()?
            != request.reference.source_attachments_digest().as_str()
    {
        return Err(checkpoint_error(
            ErrorCode::Unsupported,
            "native CRIU restore v1 requires the source configuration, source attachments, shared-host-kernel isolation, and no TEE launch",
        ));
    }
    Ok(())
}

fn restore_request_digest(
    request: &DriverRestoreRequest,
    agent_request: &AgentCreateRequest,
) -> Result<CheckpointDigest> {
    let fingerprint = RestoreRequestFingerprint {
        schema_version: RESTORE_JOURNAL_REQUEST_SCHEMA_V1,
        context: &request.context,
        target: &request.target,
        bundle: &request.bundle,
        artifact_path: &request.artifact_path,
        isolation: &request.isolation,
        io: &request.io,
        attachment_contract: &request.attachment_contract,
        tee_launch: &request.tee_launch,
        reference: &request.reference,
        runtime_artifact: &request.runtime_artifact,
        agent_request,
    };
    let encoded = canonical_json_bytes(&fingerprint).map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("failed to encode native restore request fingerprint: {error}"),
        )
    })?;
    CheckpointDigest::new(format!("sha256:{:x}", Sha256::digest(encoded)))
}

async fn reset_restore_work(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        for name in ["restore.pid", "restore.log"] {
            let entry = path.join(name);
            match std::fs::symlink_metadata(&entry) {
                Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                    std::fs::remove_file(&entry).map_err(|error| {
                        io_error("remove retained restore work file", &entry, error)
                    })?;
                }
                Ok(_) => {
                    return Err(checkpoint_error(
                        ErrorCode::PermissionDenied,
                        format!(
                            "retained restore work entry is not a file: {}",
                            entry.display()
                        ),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(io_error(
                        "inspect retained restore work file",
                        &entry,
                        error,
                    ));
                }
            }
        }
        std::fs::File::open(&path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync retained restore work directory", &path, error))
    })
    .await
    .map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("restore work reset task failed: {error}"),
        )
    })?
}
